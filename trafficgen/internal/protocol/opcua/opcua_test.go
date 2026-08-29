package opcua

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestBuildHELAndACKLengths(t *testing.T) {
	hel, err := BuildHEL("opc.tcp://192.0.2.1:4840")
	if err != nil {
		t.Fatal(err)
	}
	if string(hel[:4]) != "HELF" {
		t.Fatalf("prefix %q", hel[:4])
	}
	if got := binary.LittleEndian.Uint32(hel[4:8]); got != uint32(len(hel)) {
		t.Fatalf("HEL size=%d len=%d", got, len(hel))
	}
	ack, err := BuildACK()
	if err != nil {
		t.Fatal(err)
	}
	if string(ack[:4]) != "ACKF" {
		t.Fatalf("prefix %q", ack[:4])
	}
	if got := binary.LittleEndian.Uint32(ack[4:8]); got != 28 || got != uint32(len(ack)) {
		t.Fatalf("ACK size=%d len=%d", got, len(ack))
	}
}

func TestBuildOPNChannelProgression(t *testing.T) {
	// case opcua_hello_ack/open_none: OPN request carries secureChannelID=0
	// (off62 00000000); the response carries the server-assigned id 1
	// (off62 01000000).
	req, err := BuildOPN(0, "none")
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(req[8:12]); got != 0 {
		t.Fatalf("req channel=%d want 0", got)
	}
	resp, err := BuildOPN(1, "none")
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(resp[8:12]); got != 1 {
		t.Fatalf("resp channel=%d want 1", got)
	}
	if _, err := BuildOPN(1, "sign"); err != nil {
		t.Fatal(err)
	}
}

func TestBuildMSGHeaderLayout(t *testing.T) {
	// case opcua_write: MSG body starts with secureChannelID=1 (off62
	// 01000000) then tokenID=1000 (off66 e8030000).
	msg, err := BuildMSG(1, 0x3e8, 2, 3, 631, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg[:4]) != "MSGF" {
		t.Fatalf("prefix %q", msg[:4])
	}
	if got := binary.LittleEndian.Uint32(msg[4:8]); got != uint32(len(msg)) {
		t.Fatalf("size=%d len=%d", got, len(msg))
	}
	if got := binary.LittleEndian.Uint32(msg[8:12]); got != 1 {
		t.Fatalf("channel=%d want 1", got)
	}
	if got := binary.LittleEndian.Uint32(msg[12:16]); got != 0x3e8 {
		t.Fatalf("token=%d want 1000", got)
	}
}

func TestBuildCLOLayout(t *testing.T) {
	clo, err := BuildCLO(1, 0x3e8, 4, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(clo[:4]) != "CLOF" {
		t.Fatalf("prefix %q", clo[:4])
	}
	if got := binary.LittleEndian.Uint32(clo[8:12]); got != 1 {
		t.Fatalf("channel=%d want 1", got)
	}
}

func TestGeneratorEmitsMessageFramesOnly(t *testing.T) {
	// Event mode: the tcp layer owns handshake/teardown; the generator must
	// emit ONLY the UA message frames (HEL..CLOresp).
	var events []layers.MessageEvent
	err := (&OPCUAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{OPCUA: &core.OPCUAConfig{Close: true}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 { // HEL,ACK,OPN,OPNresp,CLO,CLOresp
		t.Fatalf("events=%d want 6 (no read, close)", len(events))
	}
	kinds := []string{"HELF", "ACKF", "OPNF", "OPNF", "CLOF", "CLOF"}
	for i, k := range kinds {
		if string(events[i].Bytes[:4]) != k {
			t.Fatalf("event %d=%q want %q", i, events[i].Bytes[:4], k)
		}
	}
	// directions: up,down,up,down,up,down
	for i, up := range []bool{true, false, true, false, true, false} {
		if events[i].Up != up {
			t.Fatalf("event %d up=%v want %v", i, events[i].Up, up)
		}
	}
}

func TestGeneratorReadPairPerOp(t *testing.T) {
	// case opcua_open_none: one read op (2 node ids) → ONE MSG pair.
	var events []layers.MessageEvent
	err := (&OPCUAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{OPCUA: &core.OPCUAConfig{
			Read:  []core.OPCUANodeRead{{NodeIDs: []string{"ns=0;i=1001", "ns=0;i=1002"}, AttributeID: 13}},
			Close: true,
		}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	msgs := 0
	for _, ev := range events {
		if string(ev.Bytes[:4]) == "MSGF" {
			msgs++
		}
	}
	if msgs != 2 {
		t.Fatalf("MSG frames=%d want 2 (req+resp)", msgs)
	}
}

func TestGeneratorSessionsNExchanges(t *testing.T) {
	// case opcua_multi_session: sessions=3 → 3 MSG exchanges on one channel.
	var events []layers.MessageEvent
	err := (&OPCUAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{OPCUA: &core.OPCUAConfig{
			Sessions: 3,
			Read:     []core.OPCUANodeRead{{NodeIDs: []string{"ns=1;i=1001"}}},
			Close:    true,
		}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	msgs := 0
	for _, ev := range events {
		if string(ev.Bytes[:4]) == "MSGF" {
			msgs++
		}
	}
	if msgs != 6 {
		t.Fatalf("MSG frames=%d want 6 (3 exchanges)", msgs)
	}
}

func TestGeneratorErrorInjectAffectsResponse(t *testing.T) {
	// cases opcua_bad_node / opcua_denied: the injected error appears in the
	// MSG response payload (request payload stays empty).
	var events []layers.MessageEvent
	err := (&OPCUAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{OPCUA: &core.OPCUAConfig{
			Read:        []core.OPCUANodeRead{{NodeIDs: []string{"ns=0;i=9999"}}},
			ErrorInject: &core.OPCUAErrInject{Op: "bad_node"},
			Close:       true,
		}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	var reqPayload, respPayload []byte
	for _, ev := range events {
		if string(ev.Bytes[:4]) == "MSGF" {
			if ev.Up && reqPayload == nil {
				reqPayload = ev.Bytes
			} else if !ev.Up && respPayload == nil {
				respPayload = ev.Bytes
			}
		}
	}
	if reqPayload == nil || respPayload == nil {
		t.Fatal("missing MSG req/resp")
	}
	// The injected status rides ResponseHeader.ServiceResult: frame = UA
	// header (8) + symmetric header (16) + TypeId (4) = 28, ResponseHeader
	// timestamp(8)+handle(4) → ServiceResult at 40 (little-endian 00 00 34 80).
	if got := binary.LittleEndian.Uint32(respPayload[40:44]); got != 0x80340000 {
		t.Fatalf("ServiceResult=%#x want 0x80340000", got)
	}
	// Node statuses stay Good: body starts at frame offset 28; ResponseHeader
	// is 24 → results count@52, results[0]@56.
	if got := binary.LittleEndian.Uint32(respPayload[56:60]); got != 0 {
		t.Fatalf("results[0]=%#x want Good", got)
	}
}

func TestGeneratorPublishKeepAliveSemantics(t *testing.T) {
	// case opcua_subscribe note: the two Publish responses are (1) a
	// notification (DataChangeNotification in notificationData) and (2) a
	// keep-alive (EMPTY notificationData). Both carry TypeId 827.
	var events []layers.MessageEvent
	err := (&OPCUAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{OPCUA: &core.OPCUAConfig{
			Subscription: &core.OPCUASubConfig{
				PublishingIntervalMs: 1000,
				PublishCount:         2,
				KeepAlive:            true,
				MaxKeepAliveCount:    100,
				MonitoredNodes:       []string{"ns=0;i=1001"},
			},
			Close: true,
		}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	var pubResp [][]byte
	for _, ev := range events {
		if string(ev.Bytes[:4]) == "MSGF" && !ev.Up && binary.LittleEndian.Uint16(ev.Bytes[26:28]) == 827 {
			pubResp = append(pubResp, ev.Bytes)
		}
	}
	if len(pubResp) != 2 {
		t.Fatalf("publish responses=%d want 2", len(pubResp))
	}
	// Frame: UA(8) + symmetric(16) + TypeId(4) = 28, ResponseHeader(24) →
	// subId(4)@52 + availSeq(4)@56 + more(1)@60 + seqNo(4)@61 + publishTime(8)
	// @65 → notificationData count at 73: first = 1 (notification),
	// second = null (keep-alive).
	// Frame base 24 + subscriptionId(4) + availSeq(4) + more(1) + seqNo(4)
	// + publishTime(8) = 45 → notificationData count at 69-24=... frame
	// offsets: count = 24+4+4+1+4+8 = 45.
	first := binary.LittleEndian.Uint32(pubResp[0][73:77])
	second := binary.LittleEndian.Uint32(pubResp[1][73:77])
	if first != 1 {
		t.Fatalf("first publish notificationData count=%d want 1", first)
	}
	if second != 0xFFFFFFFF {
		t.Fatalf("keep-alive notificationData=%#x want null", second)
	}
}

func TestValidateRejectsMalformedConfig(t *testing.T) {
	p := Planner{}
	cases := []struct {
		name string
		cfg  *core.OPCUAConfig
		want string
	}{
		{"mode", &core.OPCUAConfig{SecurityMode: "bad"}, "security_mode"},
		{"size", &core.OPCUAConfig{BadMessageSize: true}, "MessageSize"},
		{"length", &core.OPCUAConfig{BadLength: true}, "length"},
		{"channel", &core.OPCUAConfig{SkipChannel: true, Read: []core.OPCUANodeRead{{NodeIDs: []string{"ns=0;i=1"}}}}, "secureChannel"},
		{"sessions_range", &core.OPCUAConfig{Sessions: -1}, "sessions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Validate(core.FlowSpec{OPCUA: tc.cfg})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestLayerGeneratorRegistered(t *testing.T) {
	g, err := layers.NewLayerGenerator("opcua")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "opcua" {
		t.Fatalf("name=%q", g.Name())
	}
}

func TestEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config（nil OPCUA）默认化（close），Validate/Generate 均产默认流。
	spec := core.FlowSpec{}
	p := Planner{}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("empty config Validate err: %v", err)
	}

	var events []layers.MessageEvent
	err := (&OPCUAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatalf("empty config Generate err: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config generated 0 events")
	}
}

func TestGeneratorSubscriptionPairs(t *testing.T) {
	// case opcua_subscribe: 5 request/response pairs (CreateSubscription,
	// CreateMonitoredItems, SetPublishingMode, Publish notification,
	// Publish keep-alive) = 10 MSG frames; must encode without panic.
	var events []layers.MessageEvent
	err := (&OPCUAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{OPCUA: &core.OPCUAConfig{
			Subscription: &core.OPCUASubConfig{
				PublishingIntervalMs: 1000,
				PublishCount:         2,
				KeepAlive:            true,
				MaxKeepAliveCount:    100,
				MonitoredNodes:       []string{"ns=0;i=1001"},
			},
			Close: true,
		}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	msgs := 0
	for _, ev := range events {
		if string(ev.Bytes[:4]) == "MSGF" {
			msgs++
		}
	}
	if msgs != 10 {
		t.Fatalf("MSG frames=%d want 10 (5 pairs)", msgs)
	}
	if len(events) != 16 { // 4 (HEL/ACK/OPNx2) + 10 MSG + CLO pair
		t.Fatalf("events=%d want 16", len(events))
	}
}
