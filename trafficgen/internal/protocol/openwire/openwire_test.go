package openwire

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// OpenWire 终结层测试（B5 消息中间件）——全部从 50-openwire-testcase.md 与
// packet-openwire.c 的字段顺序派生：builder 逐字节断言（字段顺序/宽度/类型
// 字节）、validator 锚词表（design §4 负例锚点）、生成器事件折叠与自驱
// 完整包路径。

// ---- builder 字节级断言 ----

// TestWireFormatInfoBytes pins the negotiation command: [len=22][01]
// "ActiveMQ" [version=12] [data=0] [propsLen=4] [mapCount=0] ——与 dissector
// 的 magic@5/version@13/data@17/length@18/map@22 一一对应，总 26 字节且
// length 字段覆盖其后全部字节。
func TestWireFormatInfoBytes(t *testing.T) {
	got := BuildWireFormatInfo(12)
	want := []byte{
		0x00, 0x00, 0x00, 0x16, // length = 22
		0x01, // WireFormatInfo
		'A', 'c', 't', 'i', 'v', 'e', 'M', 'Q',
		0x00, 0x00, 0x00, 0x0c, // version 12
		0x00,             // data (tight/cache 未置位)
		0x00, 0x00, 0x00, 0x04, // properties length
		0x00, 0x00, 0x00, 0x00, // map count 0
	}
	if len(got) != len(want) {
		t.Fatalf("len %d, want %d (% x)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("byte %d = %#02x, want %#02x (full: % x)", i, got[i], want[i], got)
		}
	}
	if got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != byte(len(got)-4) {
		t.Errorf("length field must cover every byte after itself")
	}
}

// TestConnectionInfoBytes pins the command framing and the ConnectionInfo
// field order (dissector: connectionid/clientid/password/username/brokerpath/
// 5×BOOLEAN 裸字节)。
func TestConnectionInfoBytes(t *testing.T) {
	e := &core.OpenWireEvent{}
	fields := buildConnectionInfoFields(e, "client-a")
	want := []byte{
		0x01, 0x78, // notnull + CONNECTION_ID(120)
		0x01, 0x00, 0x08, 'c', 'l', 'i', 'e', 'n', 't', '-', 'a', // value string
		0x01, 0x00, 0x08, 'c', 'l', 'i', 'e', 'n', 't', '-', 'a', // clientid
		0x00,       // password null
		0x00,       // username null
		0x01, 0x00, 0x00, // brokerpath empty object array
		0x00, 0x00, 0x00, 0x00, 0x00, // 5 booleans
	}
	if hex.EncodeToString(fields) != hex.EncodeToString(want) {
		t.Fatalf("fields = % x, want % x", fields, want)
	}
	frame := frameCommand(cmdConnectionInfo, 1, true, fields)
	if frame[4] != cmdConnectionInfo {
		t.Errorf("type byte = %#02x", frame[4])
	}
	if got := uint32(frame[5])<<24 | uint32(frame[6])<<16 | uint32(frame[7])<<8 | uint32(frame[8]); got != 1 {
		t.Errorf("commandId = %d, want 1", got)
	}
	if frame[9] != 1 {
		t.Errorf("responseRequired = %d, want 1", frame[9])
	}
	if wantLen := 4 + 1 + 4 + 1 + len(fields); len(frame) != wantLen {
		t.Errorf("frame len %d, want %d (length field covers all after itself)", len(frame), wantLen)
	}
	if declared := uint32(frame[0])<<24 | uint32(frame[1])<<16 | uint32(frame[2])<<8 | uint32(frame[3]); declared != uint32(len(frame)-4) {
		t.Errorf("declared length %d, want %d", declared, len(frame)-4)
	}
}

// TestSessionProducerConsumerInfoBytes pins the ID object layouts: SessionId
// (0x79) connectionId string + value long; ProducerId (0x7b) / ConsumerId
// (0x7a) connectionId + value + session。
func TestSessionProducerConsumerInfoBytes(t *testing.T) {
	sess := buildSessionInfoFields(&core.OpenWireEvent{SessionID: 7}, "c1")
	wantSess := []byte{
		0x01, 0x79, // notnull + SESSION_ID(121)
		0x01, 0x00, 0x02, 'c', '1',
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
	}
	if hex.EncodeToString(sess) != hex.EncodeToString(wantSess) {
		t.Errorf("session = % x, want % x", sess, wantSess)
	}

	prod, err := buildProducerInfoFields(&core.OpenWireEvent{
		SessionID: 3, ProducerID: 5, Destination: "queue://orders",
	}, "c1")
	if err != nil {
		t.Fatalf("producer: %v", err)
	}
	wantProdPrefix := []byte{
		0x01, 0x7b, // PRODUCER_ID(123)
		0x01, 0x00, 0x02, 'c', '1',
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // value 5
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // session 3
		0x01, 0x64, // destination QUEUE(100)
		0x01, 0x00, 0x06, 'o', 'r', 'd', 'e', 'r', 's',
		0x01, 0x00, 0x00, // brokerpath
		0x00,             // dispatchasync
		0x00, 0x00, 0x00, 0x00, // windowsize
	}
	if !bytesEqual(prod, wantProdPrefix) {
		t.Errorf("producer = % x, want % x", prod, wantProdPrefix)
	}

	cons, err := buildConsumerInfoFields(&core.OpenWireEvent{
		SessionID: 3, ConsumerID: 9, Destination: "topic://events", AckMode: "client",
	}, "c1")
	if err != nil {
		t.Fatalf("consumer: %v", err)
	}
	if cons[1] != 0x7a {
		t.Errorf("consumer type byte = %#02x, want 0x7a", cons[1])
	}
	// prefetchsize 在 destination 之后（byte 偏移 = 2+12+13+... 用值锚定）。
	if !bytesContainsBytes(cons, []byte{0x00, 0x00, 0x03, 0xe8}) { // 1000
		t.Errorf("default prefetch 1000 missing in % x", cons)
	}
}

// TestMessageBytes pins the 29-field Message layout: 前缀 producer/destination、
// transactionid null（无事务）或 LocalTransactionId(0x6f)、messageid(0x6e)
// 嵌套 ProducerId + 双 LONG、persistent 字节、priority 裸值、body
// [notNull][4B len][bytes]、尾部 cluster/brokerIn/brokerOut。
func TestMessageBytes(t *testing.T) {
	e := &core.OpenWireEvent{
		SessionID: 2, ProducerID: 4, Destination: "queue://orders",
		Persistent: true, Priority: 6, Body: "hello",
	}
	fields, err := buildMessageFields(e, "c1", 11, 0, false)
	if err != nil {
		t.Fatalf("message: %v", err)
	}
	// producerid: [01 7b][01 00 02 c 1][value 4][session 2]
	if fields[0] != 0x01 || fields[1] != 0x7b {
		t.Fatalf("producerid prefix = % x", fields[:2])
	}
	// 找 destination 队列名。
	if !bytesContainsBytes(fields, []byte{0x01, 0x00, 0x06, 'o', 'r', 'd', 'e', 'r', 's'}) {
		t.Errorf("destination name missing")
	}
	if !bytesContainsBytes(fields, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b}) {
		t.Errorf("messageid producerSequenceId 11 missing")
	}
	// persistent=1，随后 8B expiration，再 priority=6（dissector 顺序：
	// persistent BOOLEAN → expiration LONG → priority BYTE）。
	pi := indexOf(fields, []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x06})
	if pi < 0 {
		t.Errorf("persistent+expiration+priority bytes missing in % x", fields)
	}
	if !bytesContainsBytes(fields, []byte{0x01, 0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}) {
		t.Errorf("body [notNull][len=5]hello missing")
	}
	// 无事务：transactionid 恒 null（notnull=0 出现在 destination 名之后）。

	// 有事务：LocalTransactionId(0x6f) = value LONG + connectionid CACHED。
	txFields, err := buildMessageFields(e, "c1", 11, 42, true)
	if err != nil {
		t.Fatalf("tx message: %v", err)
	}
	if !bytesContainsBytes(txFields, []byte{
		0x01, 0x6f,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, // 42
		0x01, 0x78, // connectionid
		0x01, 0x00, 0x02, 'c', '1',
	}) {
		t.Errorf("LocalTransactionId encoding missing in % x", txFields)
	}
}

// TestMessageDispatchBytes pins the nested message: [notNull][type=23]
// [cmdId 4B][respReq 1B][Message fields] ——没有 4B 长度前缀也没有第二个
// type 字节（frameCommand 只属于顶层命令；NESTED 分支由 dissector 的
// type-23 复杂路径自读 commandId/responseRequired）。
func TestMessageDispatchBytes(t *testing.T) {
	e := &core.OpenWireEvent{
		SessionID: 1, ConsumerID: 2, Destination: "topic://events", Redelivery: 3,
		ProducerID: 4,
	}
	fields, err := buildMessageDispatchFields(e, "c1", 9, 77)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if fields[0] != 0x01 || fields[1] != 0x7a {
		t.Fatalf("consumerid prefix = % x", fields[:2])
	}
	// consumerid 块 23B（[01 7a] + conn string 5 + value 8 + session 8）+
	// destination 块 11B（[01 65] + [01 00 06 "events"]）→ 嵌套 message
	// 起点 34。
	inner := fields[34:]
	if inner[0] != 0x01 || inner[1] != cmdActiveMQMessage {
		t.Fatalf("nested message prefix = % x, want [01][17]", inner[:2])
	}
	cmdID := uint32(inner[2])<<24 | uint32(inner[3])<<16 | uint32(inner[4])<<8 | uint32(inner[5])
	if cmdID != 77 {
		t.Errorf("nested commandId = %d, want 77", cmdID)
	}
	if inner[6] != 0 {
		t.Errorf("nested responseRequired = %d, want 0 (broker dispatch)", inner[6])
	}
	// 嵌套内 messageid producerSequenceId = 9。
	if !bytesContainsBytes(inner, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09}) {
		t.Errorf("nested message sequence 9 missing")
	}
	// 顶层尾部 redeliverycounter = 3。
	if !bytesContainsBytes(fields[len(fields)-4-9:], []byte{0x00, 0x00, 0x00, 0x03}) {
		t.Errorf("redelivery 3 missing in tail % x", fields[len(fields)-13:])
	}
}

// TestMessageAckBytes pins acktype byte placement and message count.
func TestMessageAckBytes(t *testing.T) {
	e := &core.OpenWireEvent{
		SessionID: 1, ConsumerID: 2, Destination: "queue://orders",
		AckMode: "individual", ProducerID: 4,
	}
	fields, err := buildMessageAckFields(e, "c1", 9)
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	// acktype = INDIVIDUAL(3) 位于 consumerid 之后：[dest][00][consumerid][03]。
	if !bytesContainsBytes(fields, []byte{0x03}) {
		t.Errorf("acktype 3 missing")
	}
	idx := indexOf(fields, []byte{0x01, 0x00, 0x02, 'c', '1',
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	if idx < 0 {
		t.Fatalf("consumerid block missing in % x", fields)
	}
	if fields[idx+21] != 3 {
		t.Errorf("byte after consumerid = %d, want acktype 3", fields[idx+21])
	}
	if !bytesContainsBytes(fields[len(fields)-4:], []byte{0x00, 0x00, 0x00, 0x01}) {
		t.Errorf("messagecount 1 missing in tail % x", fields[len(fields)-4:])
	}
}

// TestTransactionResponseExceptionRemoveShutdownBytes pins the remaining
// command layouts.
func TestTransactionResponseExceptionRemoveShutdownBytes(t *testing.T) {
	// TransactionInfo：connectionid + LocalTransactionId + type 字节
	//（begin=0/commit=2/rollback=4，packet-openwire.c 事务类型表）。
	for kind, wantType := range map[string]byte{"begin": 0, "commit": 2, "rollback": 4} {
		fields, err := buildTransactionInfoFields(&core.OpenWireEvent{
			Transaction: &core.OpenWireTransaction{ID: 5, Kind: kind},
		}, "c1")
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if fields[len(fields)-1] != wantType {
			t.Errorf("%s type byte = %d, want %d", kind, fields[len(fields)-1], wantType)
		}
	}
	// Response = [4B correlationId]。
	resp := buildResponseFields(9)
	if len(resp) != 4 || resp[3] != 9 {
		t.Errorf("response = % x, want 4-byte correlation 9", resp)
	}
	// ExceptionResponse = correlation + THROWABLE(class/message/depth 0)。
	exc := buildExceptionResponseFields(9, "boom")
	if !bytesContainsBytes(exc, []byte{0x01, 0x00, 0x04, 'b', 'o', 'o', 'm'}) {
		t.Errorf("exception message missing in % x", exc)
	}
	if exc[len(exc)-2] != 0 || exc[len(exc)-1] != 0 {
		t.Errorf("stackTraceDepth must be 0 in % x", exc)
	}
	// RemoveInfo（consumer 级）：objectid = ConsumerId。
	rem := buildRemoveInfoFields(&core.OpenWireEvent{SessionID: 1, ConsumerID: 3}, "c1")
	if rem[0] != 0x01 || rem[1] != 0x7a {
		t.Errorf("remove objectid prefix = % x, want [01][7a]", rem[:2])
	}
	// ShutdownInfo：帧长恰 10（4+1+4+1）。
	shutdown := frameCommand(cmdShutdownInfo, 1, false, nil)
	if len(shutdown) != 10 {
		t.Errorf("shutdown frame len %d, want 10", len(shutdown))
	}
}

// TestCommandFramingInvariant: every built command frame's 4-byte length
// field equals (total - 4) and total >= 4 + minCommandBytes ——对应
// neg_short_frame/length_overrun 的线不变式。
func TestCommandFramingInvariant(t *testing.T) {
	events := []core.OpenWireEvent{
		{Kind: "connection_info"},
		{Kind: "session_info", SessionID: 1},
		{Kind: "producer_info", SessionID: 1, ProducerID: 1, Destination: "queue://q"},
		{Kind: "consumer_info", SessionID: 1, ConsumerID: 1, Destination: "topic://t"},
		{Kind: "message", SessionID: 1, ProducerID: 1, Destination: "queue://q", Body: "x"},
		{Kind: "ack", SessionID: 1, ConsumerID: 1, Destination: "queue://q", MessageID: "m1"},
		{Kind: "transaction", Transaction: &core.OpenWireTransaction{ID: 1, Kind: "commit"}},
		{Kind: "remove", SessionID: 1, ConsumerID: 1},
		{Kind: "shutdown"},
	}
	c := &connGen{connID: "c1", messages: map[string]msgRef{"m1": {producerID: 1, seq: 1}}}
	for _, e := range events {
		frame, err := buildEventCommand(c, &e, nil)
		if err != nil {
			t.Fatalf("%s: %v", e.Kind, err)
		}
		declared := uint32(frame[0])<<24 | uint32(frame[1])<<16 | uint32(frame[2])<<8 | uint32(frame[3])
		if declared != uint32(len(frame)-4) {
			t.Errorf("%s: declared length %d, want %d", e.Kind, declared, len(frame)-4)
		}
		if declared < minCommandBytes {
			t.Errorf("%s: declared length %d below minimum %d", e.Kind, declared, minCommandBytes)
		}
	}
}

// TestDestinationAndAckModeParsing: queue:// → 0x64, topic:// → 0x65, 其它
// 前缀/空名拒绝；ack_mode 四档映射到固定字节。
func TestDestinationAndAckModeParsing(t *testing.T) {
	if b, name, err := destinationParts("queue://orders"); err != nil || b != objActiveMQQueue || name != "orders" {
		t.Errorf("queue parse: %v %d %q", err, b, name)
	}
	if b, _, err := destinationParts("topic://events"); err != nil || b != objActiveMQTopic {
		t.Errorf("topic parse: %v %d", err, b)
	}
	for _, bad := range []string{"", "orders", "ftp://x", "queue://", "topic://"} {
		if _, _, err := destinationParts(bad); err == nil {
			t.Errorf("destination %q: want error", bad)
		}
	}
	want := map[string]byte{"": 0, "auto": 0, "client": 2, "individual": 3, "dups_ok": 0}
	for mode, b := range want {
		got, ok := ackTypeByte(mode)
		if !ok || got != b {
			t.Errorf("ackTypeByte(%q) = %d,%v want %d", mode, got, ok, b)
		}
	}
	if _, ok := ackTypeByte("bogus"); ok {
		t.Errorf("ackTypeByte(bogus): want !ok")
	}
	if messageSeqOf("m7") != 7 || messageSeqOf("key-42") != 42 || messageSeqOf("nope") != 0 {
		t.Errorf("messageSeqOf mapping wrong")
	}
}

// ---- validator 锚词表（design §4 负例锚点，strings.Contains）----

func TestValidatorAnchors(t *testing.T) {
	neg := func(events ...core.OpenWireEvent) *core.OpenWireConfig {
		return &core.OpenWireConfig{Connections: []core.OpenWireConnection{{ConnectionID: 1, Events: events}}}
	}
	ackC := func(mode string) core.OpenWireEvent {
		return core.OpenWireEvent{Kind: "consumer_info", SessionID: 1, ConsumerID: 1, Destination: "queue://q", AckMode: mode}
	}
	cases := []struct {
		name   string
		cfg    *core.OpenWireConfig
		anchor string
	}{
		{"neg_unknown_command kind", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "bogus_frame"},
		), "command"},
		{"neg_short_frame fault", &core.OpenWireConfig{
			Connections: []core.OpenWireConnection{{ConnectionID: 1, Events: defaultEvents()}},
			WireFault:   &core.OpenWireWireFault{Kind: "short_frame"},
		}, "frame"},
		{"neg_length_overrun fault", &core.OpenWireConfig{
			Connections: []core.OpenWireConnection{{ConnectionID: 1, Events: defaultEvents()}},
			WireFault:   &core.OpenWireWireFault{Kind: "length_overrun"},
		}, "length"},
		{"neg_state_order first session", neg(
			core.OpenWireEvent{Kind: "session_info", SessionID: 1},
		), "state"},
		{"neg_state_order session before connect", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "session_info", SessionID: 1},
		), "state"},
		{"neg_correlation unknown reference", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "response", CorrelationID: 999},
		), "correlation"},
		{"neg_correlation ack unknown message", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "connection_info"},
			core.OpenWireEvent{Kind: "session_info", SessionID: 1},
			core.OpenWireEvent{Kind: "consumer_info", SessionID: 1, ConsumerID: 1, Destination: "queue://q"},
			core.OpenWireEvent{Kind: "ack", SessionID: 1, ConsumerID: 1, Destination: "queue://q", MessageID: "ghost"},
		), "message"},
		{"neg_transaction commit without begin", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "transaction", Transaction: &core.OpenWireTransaction{ID: 1, Kind: "commit"}},
		), "transaction"},
		{"neg_transaction double terminate", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "transaction", Transaction: &core.OpenWireTransaction{ID: 1, Kind: "begin"}},
			core.OpenWireEvent{Kind: "transaction", Transaction: &core.OpenWireTransaction{ID: 1, Kind: "commit"}},
			core.OpenWireEvent{Kind: "transaction", Transaction: &core.OpenWireTransaction{ID: 1, Kind: "commit"}},
		), "transaction"},
		{"neg_transaction message references closed txn", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "connection_info"},
			core.OpenWireEvent{Kind: "session_info", SessionID: 1},
			core.OpenWireEvent{Kind: "transaction", Transaction: &core.OpenWireTransaction{ID: 1, Kind: "begin"}},
			core.OpenWireEvent{Kind: "message", SessionID: 1, ProducerID: 1, Destination: "queue://q", Transaction: &core.OpenWireTransaction{ID: 9}},
		), "transaction"},
		{"neg_entity_scope producer unknown session", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "connection_info"},
			core.OpenWireEvent{Kind: "session_info", SessionID: 2},
			core.OpenWireEvent{Kind: "producer_info", SessionID: 1, ProducerID: 1, Destination: "queue://q"},
		), "entity"},
		{"neg_entity_scope cross-connection session", &core.OpenWireConfig{Connections: []core.OpenWireConnection{
			{ConnectionID: 1, Events: []core.OpenWireEvent{
				{Kind: "wire_format_info"}, {Kind: "connection_info"}, {Kind: "session_info", SessionID: 1},
			}},
			{ConnectionID: 2, Events: []core.OpenWireEvent{
				{Kind: "wire_format_info"}, {Kind: "connection_info"}, {Kind: "session_info", SessionID: 2},
				{Kind: "producer_info", SessionID: 1, ProducerID: 1, Destination: "queue://q"},
			}},
		}}, "entity"},
		{"neg_destination bad scheme", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "connection_info"},
			core.OpenWireEvent{Kind: "session_info", SessionID: 1},
			core.OpenWireEvent{Kind: "producer_info", SessionID: 1, ProducerID: 1, Destination: "ftp://x"},
		), "destination"},
		{"neg_destination empty name", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "connection_info"},
			core.OpenWireEvent{Kind: "session_info", SessionID: 1},
			core.OpenWireEvent{Kind: "producer_info", SessionID: 1, ProducerID: 1, Destination: "queue://"},
		), "destination"},
		{"neg_carrier_profile unknown profile", &core.OpenWireConfig{
			Profile:     "activemq_openwire_v99",
			Connections: []core.OpenWireConnection{{ConnectionID: 1, Events: defaultEvents()}},
		}, "profile"},
		{"neg_carrier_profile tight encoding", &core.OpenWireConfig{
			WireFormat:  &core.OpenWireWireFormat{Version: 12, TightEncoding: true},
			Connections: []core.OpenWireConnection{{ConnectionID: 1, Events: defaultEvents()}},
		}, "profile"},
		{"neg_carrier_profile cache enabled", &core.OpenWireConfig{
			WireFormat:  &core.OpenWireWireFormat{CacheEnabled: true},
			Connections: []core.OpenWireConnection{{ConnectionID: 1, Events: defaultEvents()}},
		}, "profile"},
		{"dup session in connection", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "connection_info"},
			core.OpenWireEvent{Kind: "session_info", SessionID: 1},
			core.OpenWireEvent{Kind: "session_info", SessionID: 1},
		), "session"},
		{"unknown ack_mode", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "connection_info"},
			core.OpenWireEvent{Kind: "session_info", SessionID: 1},
			ackC("bogus"),
		), "ack_mode"},
		{"unknown wire_fault kind", &core.OpenWireConfig{
			Connections: []core.OpenWireConnection{{ConnectionID: 1, Events: defaultEvents()}},
			WireFault:   &core.OpenWireWireFault{Kind: "bogus"},
		}, "unknown wire_fault"},
		{"command after shutdown", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "shutdown"},
			core.OpenWireEvent{Kind: "connection_info"},
		), "state"},
		{"bad direction", neg(
			core.OpenWireEvent{Kind: "wire_format_info"},
			core.OpenWireEvent{Kind: "message", Direction: "s2c", SessionID: 1, Destination: "queue://q"},
		), "message must be c2s"},
	}
	for _, c := range cases {
		err := ValidateConfig(c.cfg)
		if err == nil {
			t.Errorf("%s: want error, got nil", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.anchor) {
			t.Errorf("%s: error %q missing anchor %q", c.name, err.Error(), c.anchor)
		}
	}
}

// TestValidatorBoundariesLegal: 全事件种类、多连接、显式 correlation 命中、
// remove→shutdown 顺序、空 body、双栈连接声明、nil config 必须**通过**。
func TestValidatorBoundariesLegal(t *testing.T) {
	txn := func(kind string) *core.OpenWireTransaction { return &core.OpenWireTransaction{ID: 1, Kind: kind} }
	cfg := &core.OpenWireConfig{
		Profile:    "activemq_openwire_v12",
		WireFormat: &core.OpenWireWireFormat{Version: 12},
		Connections: []core.OpenWireConnection{{
			ConnectionID: 1, ClientID: "client-a", SrcPort: 40000,
			Events: []core.OpenWireEvent{
				{Kind: "wire_format_info", Direction: "c2s"},
				{Kind: "wire_format_info", Direction: "s2c"},
				{Kind: "connection_info"},
				{Kind: "connection_ack", CorrelationID: 1},
				{Kind: "session_info", SessionID: 1},
				{Kind: "session_info", SessionID: 2},
				{Kind: "producer_info", SessionID: 1, ProducerID: 1, Destination: "queue://orders"},
				{Kind: "consumer_info", SessionID: 2, ConsumerID: 1, Destination: "topic://events", AckMode: "client"},
				{Kind: "consumer_info", SessionID: 2, ConsumerID: 2, Destination: "topic://events", AckMode: "individual"},
				{Kind: "transaction", Transaction: txn("begin")},
				{Kind: "message", SessionID: 1, ProducerID: 1, Destination: "queue://orders", MessageID: "m1", Transaction: txn0()},
				{Kind: "transaction", Transaction: txn("commit")},
				{Kind: "dispatch", SessionID: 2, ConsumerID: 1, Destination: "topic://events", MessageID: "m1", Redelivery: 0},
				{Kind: "ack", SessionID: 2, ConsumerID: 1, Destination: "topic://events", MessageID: "m1", AckMode: "individual", MessageCount: 1},
				{Kind: "exception", CorrelationID: 1, Exception: "boom"},
				{Kind: "remove", SessionID: 2, ConsumerID: 1},
				{Kind: "remove", SessionID: 1},
				{Kind: "shutdown"},
			},
		}, {
			ConnectionID: 2, ClientID: "client-b", SrcPort: 40002,
			SrcIP: "2001:db8:50::10", DstIP: "2001:db8:50::20",
			Events: []core.OpenWireEvent{
				{Kind: "wire_format_info"},
				{Kind: "connection_info"},
				{Kind: "session_info", SessionID: 1},
			},
		}},
	}
	// 注意：message 的事务引用要求事务处于 open——上面 begin 在 message 之前，
	// commit 在其后，顺序合法（txn0() 只是占位，等价 {ID:1}）。
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("legal full-flow config rejected: %v", err)
	}
	if err := ValidateConfig(nil); err != nil {
		t.Errorf("nil config must be legal, got %v", err)
	}
	// connection_ack 显式 correlation 命中 commandId 1（connection_info 的
	// 自动命令号）——上面已覆盖；此处再验证默认（无显式）也合法。
	minCfg := &core.OpenWireConfig{Connections: []core.OpenWireConnection{{
		ConnectionID: 1, Events: defaultEvents(),
	}}}
	if err := ValidateConfig(minCfg); err != nil {
		t.Errorf("minimal negotiation config rejected: %v", err)
	}
}

// txn0 is a helper for the legal-flow test (message-in-open-transaction)。
func txn0() *core.OpenWireTransaction { return &core.OpenWireTransaction{ID: 1} }

// TestMessageFrameLength pins the Message frame length formula
// (len(frame) = 4 + 6 + len(fields) = 168 + len(body) for conn "client-a")
// so the pcap case JSON's segmentation/length assertions stay grounded.
func TestMessageFrameLength(t *testing.T) {
	// 空 body：fields = 158 → frame = 168。
	e := &core.OpenWireEvent{SessionID: 1, ProducerID: 1, Destination: "queue://orders"}
	fields, err := buildMessageFields(e, "client-a", 1, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 158 {
		t.Errorf("empty-body fields len %d, want 158", len(fields))
	}
	frame := frameCommand(cmdActiveMQMessage, 4, true, fields)
	if len(frame) != 168 {
		t.Errorf("empty-body frame len %d, want 168", len(frame))
	}
	// 4000B body：fields = 4158 → frame = 4168（openwire.length = 4164，
	// MSS 1460 分割 → 1460/1460/1248？以 168+4000 公式基准在 pcap 校准）。
	big := strings.Repeat("A", 4000)
	e2 := &core.OpenWireEvent{SessionID: 1, ProducerID: 1, Destination: "queue://orders", Body: big}
	fields2, err := buildMessageFields(e2, "client-a", 1, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	frame2 := frameCommand(cmdActiveMQMessage, 4, true, fields2)
	if len(fields2) != 158-1+4005 {
		t.Errorf("big-body fields len %d, want %d", len(fields2), 158-1+4005)
	}
	if len(frame2) != 4+6+158-1+4005 {
		t.Errorf("big-body frame len %d, want %d", len(frame2), 4+6+158-1+4005)
	}
}

// ---- generator 事件折叠 ----

func collectEvents(t *testing.T, cfg *core.OpenWireConfig) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{OpenWire: cfg},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := (&OpenWireGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return events
}

// TestGenerateEventFolding: 事件按序产出、方向/SrcPort 随连接携带、命令号
// 客户端/服务端各自递增、connection_ack 关联 connection_info 的命令号。
func TestGenerateEventFolding(t *testing.T) {
	cfg := &core.OpenWireConfig{Connections: []core.OpenWireConnection{{
		ConnectionID: 1, ClientID: "client-a", SrcPort: 40001,
		Events: []core.OpenWireEvent{
			{Kind: "wire_format_info"},
			{Kind: "connection_info"},
			{Kind: "connection_ack"},
			{Kind: "session_info", SessionID: 1},
			{Kind: "consumer_info", SessionID: 1, ConsumerID: 2, Destination: "queue://orders"},
			{Kind: "message", SessionID: 1, ProducerID: 1, Destination: "queue://orders", MessageID: "m1", Persistent: true},
			{Kind: "dispatch", ConsumerID: 2, Destination: "queue://orders", MessageID: "m1"},
			{Kind: "ack", SessionID: 1, ConsumerID: 2, Destination: "queue://orders", MessageID: "m1", AckMode: "individual"},
		},
	}}}
	events := collectEvents(t, cfg)
	if len(events) != 8 {
		t.Fatalf("got %d events, want 8", len(events))
	}
	wantUp := []bool{true, true, false, true, true, true, false, true}
	for i, up := range wantUp {
		if events[i].Up != up {
			t.Errorf("event %d up=%v, want %v", i, events[i].Up, up)
		}
		if events[i].SrcPort != 40001 {
			t.Errorf("event %d srcPort %d, want 40001", i, events[i].SrcPort)
		}
	}
	// 命令类型字节序列：1,3,30,4,5,23,21,22。
	wantCmd := []byte{1, 3, 30, 4, 5, 23, 21, 22}
	for i, cmd := range wantCmd {
		if events[i].Bytes[4] != cmd {
			t.Errorf("event %d command byte = %d, want %d", i, events[i].Bytes[4], cmd)
		}
	}
	// connection_ack（事件 3）的 correlationId = connection_info 的命令号 1。
	ack := events[2].Bytes
	if ack[4] != 30 {
		t.Fatalf("event 3 is not Response: % x", ack[:5])
	}
	if corr := uint32(ack[10])<<24 | uint32(ack[11])<<16 | uint32(ack[12])<<8 | uint32(ack[13]); corr != 1 {
		t.Errorf("correlationId = %d, want 1 (connection_info 命令号)", corr)
	}
	// 客户端命令号递增：wf(无) c=1, session=2, consumer=3, message=4, ack=5。
	for i, wantID := range []uint32{0, 1, 0, 2, 3, 4, 0, 5} {
		if wantID == 0 {
			continue
		}
		b := events[i].Bytes
		id := uint32(b[5])<<24 | uint32(b[6])<<16 | uint32(b[7])<<8 | uint32(b[8])
		if id != wantID {
			t.Errorf("event %d commandId = %d, want %d", i, id, wantID)
		}
	}
}

// TestGenerateMultiConnectionPorts: 第二个连接的事件携带自己的 SrcPort。
func TestGenerateMultiConnectionPorts(t *testing.T) {
	cfg := &core.OpenWireConfig{Connections: []core.OpenWireConnection{
		{ConnectionID: 1, SrcPort: 40001, Events: []core.OpenWireEvent{{Kind: "wire_format_info"}, {Kind: "connection_info"}}},
		{ConnectionID: 2, SrcPort: 40002, Events: []core.OpenWireEvent{{Kind: "wire_format_info"}, {Kind: "connection_info"}}},
	}}
	events := collectEvents(t, cfg)
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4", len(events))
	}
	if events[0].SrcPort != 40001 || events[1].SrcPort != 40001 || events[2].SrcPort != 40002 || events[3].SrcPort != 40002 {
		t.Errorf("per-connection srcPort wrong: %v", []uint16{events[0].SrcPort, events[1].SrcPort, events[2].SrcPort, events[3].SrcPort})
	}
}

// TestGenerateEmptyConfigDefaultFlow (P0b 契约)：nil config 产出最小协商流。
func TestGenerateEmptyConfigDefaultFlow(t *testing.T) {
	events := collectEvents(t, nil)
	if len(events) != 3 {
		t.Fatalf("nil config: got %d events, want 3 (wf_info/connection_info/ack)", len(events))
	}
	if events[0].Bytes[4] != cmdWireFormatInfo || events[1].Bytes[4] != cmdConnectionInfo || events[2].Bytes[4] != cmdResponse {
		t.Errorf("default flow command bytes wrong: %d %d %d", events[0].Bytes[4], events[1].Bytes[4], events[2].Bytes[4])
	}
}

// TestGenerateNilEmitMsg / TestGenerateCtxCancel: 接线错误与取消是硬错误。
func TestGenerateNilEmitMsg(t *testing.T) {
	if err := (&OpenWireGenerator{}).Generate(context.Background(), nil); err == nil {
		t.Errorf("nil request: want error")
	}
	if err := (&OpenWireGenerator{}).Generate(context.Background(), &layers.GenRequest{}); err == nil {
		t.Errorf("neither EmitMsg nor Emit: want error")
	}
}

func TestGenerateCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &core.OpenWireConfig{Connections: []core.OpenWireConnection{{
		ConnectionID: 1, Events: []core.OpenWireEvent{{Kind: "wire_format_info"}},
	}}}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{OpenWire: cfg},
		EmitMsg: func(layers.MessageEvent) error { return nil },
	}
	if err := (&OpenWireGenerator{}).Generate(ctx, req); err == nil {
		t.Errorf("cancelled ctx: want error")
	}
}

// ---- 自驱完整包路径（双栈用例）----

// TestGeneratePacketsDualFamily: 显式地址触发自驱模式——每连接
// SYN/SYN-ACK/ACK + 命令段 + FIN 挥手，L3 按连接家族装配（v4/v6 混存）。
func TestGeneratePacketsDualFamily(t *testing.T) {
	cfg := &core.OpenWireConfig{Connections: []core.OpenWireConnection{
		{ConnectionID: 1, SrcPort: 40001, Events: []core.OpenWireEvent{{Kind: "wire_format_info"}}},
		{ConnectionID: 2, SrcPort: 40002, SrcIP: "2001:db8:50::10", DstIP: "2001:db8:50::20",
			Events: []core.OpenWireEvent{{Kind: "wire_format_info"}}},
	}}
	var pkts []core.PacketConfig
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			OpenWire: cfg,
			SrcIP:    "192.0.2.10", DstIP: "198.51.100.20", SrcPort: 40001, DstPort: 61616,
			FlowID: "flow-1",
		},
		Emit: func(pkt core.PacketConfig) error {
			pkts = append(pkts, pkt)
			return nil
		},
	}
	if err := (&OpenWireGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// 每连接 = 3 握手 + 1 数据 + 4 挥手 = 8；两连接 = 16。
	if len(pkts) != 16 {
		t.Fatalf("got %d packets, want 16", len(pkts))
	}
	// 连接 1（v4）：包 0-7；连接 2（v6）：包 8-15。
	for i, pkt := range pkts {
		family := "192.0.2.10"
		if i >= 8 {
			family = "2001:db8:50::10"
		}
		if pkt.L3.SrcIP != family {
			t.Errorf("packet %d srcIP %q, want %q", i, pkt.L3.SrcIP, family)
		}
		if pkt.L3.Protocol != 6 {
			t.Errorf("packet %d protocol %d, want 6 (TCP)", i, pkt.L3.Protocol)
		}
	}
	// 握手序列 flags：SYN / SYN|ACK / ACK。
	if pkts[0].L4.Flags != 0x02 || pkts[1].L4.Flags != 0x12 || pkts[2].L4.Flags != 0x10 {
		t.Errorf("handshake flags = %#x %#x %#x", pkts[0].L4.Flags, pkts[1].L4.Flags, pkts[2].L4.Flags)
	}
	// 数据段方向/端口：up=40001→61616、down=61616→40001；payload 是完整命令帧。
	data := pkts[3]
	if data.L4.SrcPort != 40001 || data.L4.DstPort != 61616 || len(data.Payload) == 0 {
		t.Errorf("data segment wrong: %d→%d payload=%d", data.L4.SrcPort, data.L4.DstPort, len(data.Payload))
	}
	if data.Payload[4] != cmdWireFormatInfo {
		t.Errorf("data payload is not WireFormatInfo: %#02x", data.Payload[4])
	}
	// 挥手序列 flags：FIN|ACK / ACK / FIN|ACK / ACK。
	if pkts[4].L4.Flags != 0x11 || pkts[5].L4.Flags != 0x10 || pkts[6].L4.Flags != 0x11 || pkts[7].L4.Flags != 0x10 {
		t.Errorf("teardown flags = %#x %#x %#x %#x", pkts[4].L4.Flags, pkts[5].L4.Flags, pkts[6].L4.Flags, pkts[7].L4.Flags)
	}
	// seq 推进：数据段后客户端 seq = 握手初始+1（SYN 占 1）+ 帧长。
	if pkts[4].L4.Seq != pkts[3].L4.Seq+uint32(len(pkts[3].Payload)) {
		t.Errorf("FIN seq must follow data seq")
	}
	// 序号回填：FlowID + PacketIndex 全局递增。
	if pkts[0].FlowID != "flow-1" || pkts[15].PacketIndex != 15 {
		t.Errorf("flow/index backfill wrong: %q %d", pkts[0].FlowID, pkts[15].PacketIndex)
	}
}

// TestGeneratePacketsErrorPropagation: 非法事件（未知消息引用）在自驱路径
// 同样报错，不产空流。
func TestGeneratePacketsErrorPropagation(t *testing.T) {
	cfg := &core.OpenWireConfig{Connections: []core.OpenWireConnection{{
		ConnectionID: 1, SrcPort: 40001, SrcIP: "192.0.2.10", DstIP: "198.51.100.20",
		Events: []core.OpenWireEvent{
			{Kind: "wire_format_info"},
			{Kind: "ack", ConsumerID: 1, Destination: "queue://q", MessageID: "ghost"},
		},
	}}}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{OpenWire: cfg, SrcIP: "192.0.2.10", DstIP: "198.51.100.20"},
		Emit: func(core.PacketConfig) error { return nil },
	}
	err := (&OpenWireGenerator{}).Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "message") {
		t.Fatalf("want correlation error, got %v", err)
	}
}

// ---- 接口注册 ----

func TestGeneratorInterface(t *testing.T) {
	g := &OpenWireGenerator{}
	if g.Name() != "openwire" {
		t.Errorf("Name %q", g.Name())
	}
	if g.GenEvents() == nil {
		t.Errorf("GenEvents must return the event producer")
	}
	factory, err := layers.NewLayerGenerator("openwire")
	if err != nil {
		t.Fatalf("NewLayerGenerator: %v", err)
	}
	if factory.Name() != "openwire" {
		t.Errorf("registered generator name %q", factory.Name())
	}
}

// ---- helpers ----

func bytesEqual(a, b []byte) bool {
	return hex.EncodeToString(a) == hex.EncodeToString(b)
}

func bytesContainsBytes(hay, needle []byte) bool {
	return indexOf(hay, needle) >= 0
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
