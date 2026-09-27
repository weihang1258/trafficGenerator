package s7

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestBuildConnectionRequestMatchesS7Template(t *testing.T) {
	got, err := BuildConnectionRequest(&S7Config{})
	if err != nil {
		t.Fatal(err)
	}
	want := "0300001611e00000000100c0010ac1020100c2020102"
	if hex.EncodeToString(got) != want {
		t.Fatalf("CR = %x, want %s", got, want)
	}
}

func TestBuildSetupAndReadMessages(t *testing.T) {
	cfg := &S7Config{
		PDURef:   2,
		PDUSize:  480,
		Commands: []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, DBNumber: 1, Address: 0, TransportSize: 4, Length: 1}}}},
	}
	setup, err := BuildSetup(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(setup) != "0300001902f08032"+"010000000200080000f0000001000101e0" {
		t.Fatalf("setup = %x", setup)
	}
	read, err := BuildRead(cfg, cfg.Commands[0])
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(read) != "0300002002f08032"+"0100000003000e00010401120a1004000100018400000000" {
		t.Fatalf("read = %x", read)
	}
}

func TestPlannerRejectsInvalidS7Config(t *testing.T) {
	cases := []struct {
		name string
		cfg  *S7Config
		want string
	}{
		{"rosctr", &S7Config{Commands: []S7Command{{Kind: "read", ROSCTR: 9}}}, "rosctr"},
		{"area", &S7Config{Commands: []S7Command{{Kind: "read", Items: []S7Item{{Area: 0, Length: 1}}}}}, "area"},
		{"address", &S7Config{Commands: []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, Address: 0x100000, Length: 1}}}}}, "address"},
		{"transport", &S7Config{Transport: "udp"}, "udp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 102, S7: tc.cfg})
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("Validate error = %v, want %q", err, tc.want)
			}
		})
	}
}

// D-S7-85 §14 ②：三条校验收紧（G-S7-2 未知 kind / G-S7-3 transport_size
// 越界 / G-S7-4 sessions 越界）。此前三者在生成器里全部静默放行（未知 kind
// 当 read、越界 size 直落字节、sessions 无上界线性展开）——配置错误产出
// "合法"包流（假成功）。
func TestPlannerRejectsTightenedDomains(t *testing.T) {
	cases := []struct {
		name string
		cfg  *S7Config
		want string
	}{
		{"unknown_kind", &S7Config{Commands: []S7Command{{Kind: "reed", Items: []S7Item{{Area: 0x84, Length: 1}}}}}, `unknown kind "reed"`},
		{"transport_size_high", &S7Config{Commands: []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, TransportSize: 0x0a, Length: 1}}}}}, "invalid transport_size 0x0a"},
		{"transport_size_low", &S7Config{Commands: []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, TransportSize: 0xff, Length: 1}}}}}, "invalid transport_size 0xff"},
		{"sessions_over", &S7Config{Sessions: 17, Commands: []S7Command{}}, "invalid sessions 17"},
		{"sessions_negative", &S7Config{Sessions: -1, Commands: []S7Command{}}, "invalid sessions -1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 102, S7: tc.cfg})
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("Validate error = %v, want %q", err, tc.want)
			}
		})
	}
	// 边界合法值必须放行（16 会话 / size 0x09 / 空 kind 缺省 read）。
	ok := &S7Config{Sessions: 16, Commands: []S7Command{
		{Kind: "", Items: []S7Item{{Area: 0x84, TransportSize: 0x09, Length: 1}}},
		{Kind: "readsZL", SzlID: 0x132, SzlIndex: 4},
		{Kind: "keepalive"},
	}}
	if err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 102, S7: ok}); err != nil {
		t.Fatalf("boundary-legal config rejected: %v", err)
	}
}

func TestPlannerEmitsS7SessionAndLayerGeneratorEvents(t *testing.T) {
	cfg := &S7Config{Commands: []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, DBNumber: 1, Address: 0, TransportSize: 4, Length: 1}}}}}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 102, S7: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	if len(packets) < 9 {
		t.Fatalf("packets = %d, want at least 9", len(packets))
	}
	if packets[3].Payload[0] != 0x03 || packets[3].Payload[5] != 0xe0 {
		t.Fatalf("CR payload = %x", packets[3].Payload)
	}

	var events []layers.MessageEvent
	err = (&S7Generator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{S7: cfg, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 102}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 6 || !events[0].Up || events[1].Up {
		t.Fatalf("events = %#v", events)
	}
}

func TestLayerGeneratorMultiSessionSrcPorts(t *testing.T) {
	// count 型多会话（P0a 模式）：sessions=2 每会话一条独立 TCP 连接，事件
	// 源端口 = 顶层 src_port + i，tcp 层据 SrcPort 判定会话边界（挥旧握新）。
	cfg := &S7Config{Sessions: 2, Commands: []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, DBNumber: 1, Address: 0, TransportSize: 4, Length: 1}}}}}
	var ports []uint16
	err := (&S7Generator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{S7: cfg, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 102},
		EmitMsg: func(ev layers.MessageEvent) error {
			ports = append(ports, ev.SrcPort)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Generate multi-session: %v", err)
	}
	if len(ports) < 2 || ports[0] != 12345 || ports[len(ports)-1] != 12346 {
		t.Fatalf("event src ports=%v, want session 1 on 12345 and session 2 on 12346", ports)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
