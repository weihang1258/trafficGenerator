package fins

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func testSpec(cfg *FINSConfig) core.FlowSpec {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: DefaultPort}
	return AttachSpec(spec, cfg)
}

func TestFINSGeneratorRejectsMissingEmitter(t *testing.T) {
	err := (&FINSGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{FINS: &FINSConfig{}}})
	if err == nil || !strings.Contains(err.Error(), "EmitMsg") {
		t.Fatalf("Generate() = %v, want missing EmitMsg error", err)
	}
}

func TestFINSGeneratorEmitsUDPRequestAndResponse(t *testing.T) {
	cfg := &FINSConfig{Transport: "udp", SID: 7, Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 1}}}
	var events []layers.MessageEvent
	err := (&FINSGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{FINS: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || !events[0].Up || events[1].Up {
		t.Fatalf("events = %#v, want request up and response down", events)
	}
	want, err := BuildFrameWithConfig(cfg, cfg.Commands[0], false, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(events[0].Bytes, want) {
		t.Fatalf("request = % X, want % X", events[0].Bytes, want)
	}
}

func TestFINSGeneratorWrapsTCPFrameSend(t *testing.T) {
	cfg := &FINSConfig{Transport: "tcp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}}}
	var event layers.MessageEvent
	err := (&FINSGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{FINS: cfg},
		EmitMsg: func(ev layers.MessageEvent) error {
			if len(event.Bytes) == 0 {
				event = ev
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(event.Bytes) < 16 || string(event.Bytes[:4]) != "FINS" {
		t.Fatalf("event bytes = % X, want FINS/TCP envelope", event.Bytes)
	}
	if got := binary.BigEndian.Uint32(event.Bytes[4:8]); got != uint32(len(event.Bytes)-8) {
		t.Fatalf("length = %d, want %d", got, len(event.Bytes)-8)
	}
}

func TestFINSResponseUsesResponseICF(t *testing.T) {
	cfg := &FINSConfig{Transport: "udp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, ICF: 0x80, MemoryArea: "dm", Items: 1}}}
	var events []layers.MessageEvent
	if err := (&FINSGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{FINS: cfg}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }}); err != nil {
		t.Fatal(err)
	}
	if got := events[1].Bytes[0]; got != 0xC0 {
		t.Fatalf("response ICF = 0x%02X, want 0xC1", got)
	}
}

func TestFINSValidatorRejectsReservedCommandICF(t *testing.T) {
	cfg := &FINSConfig{Commands: []FINSCommand{{Command: CommandMemoryAreaRead, ICF: 0x20, MemoryArea: "dm", Items: 1}}}
	if err := NewPlanner().Validate(testSpec(cfg)); err == nil || !strings.Contains(err.Error(), "icf") {
		t.Fatalf("Validate() = %v, want command ICF validation error", err)
	}
}

func TestFINSValidatorRejectsAreaSpecificAddressBounds(t *testing.T) {
	cfg := &FINSConfig{Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "cio", Address: 6144, Items: 1}}}
	if err := NewPlanner().Validate(testSpec(cfg)); err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("Validate() = %v, want CIO address validation error", err)
	}
}

func TestFINSDirectConfigDefaultsSIDAuto(t *testing.T) {
	cfg := &FINSConfig{Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}, {Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if got := []byte{packets[0].Payload[9], packets[2].Payload[9]}; !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("request SIDs = %02X, want 01 02", got)
	}
}

func TestFINSGeneratorHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := (&FINSGenerator{}).Generate(ctx, &layers.GenRequest{
		Meta:    layers.FlowMeta{FINS: &FINSConfig{Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}}}},
		EmitMsg: func(layers.MessageEvent) error { called = true; return nil },
	})
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("Generate() = %v, emitter called=%v, want canceled before emission", err, called)
	}
}

func TestFINSLayerValidatorAcceptsMultiSession(t *testing.T) {
	// count 型多会话（P0a 模式）合法：sessions=2 由生成器逐会话展开独立端口，
	// validator 不再拒绝。
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: DefaultPort, Metadata: map[string]interface{}{MetadataKey: &FINSConfig{Sessions: 2}}}
	if err := layers.NewChainPlanner("fins").Validate(spec); err != nil {
		t.Fatalf("validator error = %v, want nil (multi-session legal)", err)
	}
}

func TestFINSLayerGeneratorMultiSessionSrcPorts(t *testing.T) {
	// 生成器逐会话发事件，UDP 源端口 = 顶层 src_port + i。
	cfg := &FINSConfig{Sessions: 2, Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}}}
	var ports []uint16
	gen := &FINSGenerator{}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{FINS: cfg, SrcPort: 1245},
		EmitMsg: func(ev layers.MessageEvent) error { ports = append(ports, ev.SrcPort); return nil },
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate multi-session: %v", err)
	}
	if len(ports) < 4 || ports[0] != 1245 || ports[len(ports)-1] != 1246 {
		t.Fatalf("event src ports=%v, want session 1 on 1245 and session 2 on 1246", ports)
	}
}

func TestFINSLayerValidatorRejectsTransportCarrierMismatch(t *testing.T) {
	for _, tc := range []struct{ name, carrier, transport string }{
		{name: "tcp carrier with udp config", carrier: "tcp", transport: "udp"},
		{name: "udp carrier with tcp config", carrier: "udp", transport: "tcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: DefaultPort, Metadata: map[string]interface{}{MetadataKey: &FINSConfig{Transport: tc.transport, Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}}}}}
			chain := []layers.Layer{{Name: "ip", Config: map[string]interface{}{}}, {Name: tc.carrier, Config: map[string]interface{}{}}, {Name: "fins", Config: map[string]interface{}{}}}
			err := layers.NewChainPlannerFromChain("fins", chain).Validate(spec)
			if err == nil || !strings.Contains(err.Error(), "carrier") {
				t.Fatalf("validator error = %v, want carrier mismatch", err)
			}
		})
	}
}

func TestFINSLayerChainInfersUDPTransport(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: DefaultPort, Metadata: map[string]interface{}{MetadataKey: &FINSConfig{Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}}}}}
	planner := layers.NewChainPlannerFromChain("fins", []layers.Layer{{Name: "ip", Config: map[string]interface{}{}}, {Name: "udp", Config: map[string]interface{}{}}, {Name: "fins", Config: map[string]interface{}{}}})
	validated, err := planner.ValidateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := collectLayerPlan(t, planner, validated)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) == 0 || packets[0].L4.Protocol != "udp" {
		t.Fatalf("packets = %#v", packets)
	}
}
func TestFINSLayerChainPlansTCPFrameSendWhenTransportOmitted(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: DefaultPort, Metadata: map[string]interface{}{MetadataKey: &FINSConfig{Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}}}}}
	planner := layers.NewChainPlannerFromChain("fins", []layers.Layer{{Name: "ip", Config: map[string]interface{}{}}, {Name: "tcp", Config: map[string]interface{}{}}, {Name: "fins", Config: map[string]interface{}{}}})
	validated, err := planner.ValidateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := collectLayerPlan(t, planner, validated)
	if err != nil {
		t.Fatal(err)
	}
	for _, packet := range packets {
		if packet.L4.Protocol == "tcp" && len(packet.Payload) > 0 {
			if !bytes.HasPrefix(packet.Payload, []byte("FINS")) {
				t.Fatalf("payload = % X", packet.Payload)
			}
			return
		}
	}
	t.Fatal("no TCP application payload")
}
func TestFINSLayerChainPlansUDPData(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: DefaultPort, Metadata: map[string]interface{}{MetadataKey: &FINSConfig{Transport: "udp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 1}}}}}
	packets, err := collectLayerPlan(t, layers.NewChainPlanner("fins"), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 2 || packets[0].L4.Protocol != "udp" {
		t.Fatalf("packets = %d", len(packets))
	}
}

func collectLayerPlan(t *testing.T, planner *layers.ChainPlanner, spec core.FlowSpec) ([]core.PacketConfig, error) {
	t.Helper()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		return nil, err
	}
	var packets []core.PacketConfig
	for packet := range ch {
		packets = append(packets, packet)
	}
	return packets, nil
}

func TestGetConfigAcceptsNumericDataArray(t *testing.T) {
	spec := core.FlowSpec{Metadata: map[string]interface{}{MetadataKey: map[string]interface{}{"commands": []interface{}{map[string]interface{}{"command": float64(CommandMemoryAreaWrite), "memory_area": "dm", "items": float64(1), "data": []interface{}{float64(0x12), float64(0x34)}}}}}}
	cfg := GetConfig(spec)
	if cfg == nil || len(cfg.Commands) != 1 || !bytes.Equal(cfg.Commands[0].Data, []byte{0x12, 0x34}) {
		t.Fatalf("GetConfig() = %#v, want one command with numeric data bytes", cfg)
	}
}

func TestValidateRejectsUnknownMemoryArea(t *testing.T) {
	cfg := &FINSConfig{Transport: "udp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "xyz_bad", Address: 1, Items: 1}}}
	if err := NewPlanner().Validate(testSpec(cfg)); err == nil || !strings.Contains(err.Error(), "memory area") {
		t.Fatalf("Validate() = %v, want memory-area error", err)
	}
}

func TestBuildMemoryAreaReadFrame(t *testing.T) {
	cfg := &FINSConfig{Transport: "udp", SID: 1, Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}}}
	request, err := BuildFrame(cfg, cfg.Commands[0], false)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x81, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x82, 0x00, 0x64, 0x00, 0x00, 0x02}
	if !bytes.Equal(request, want) {
		t.Fatalf("request = % X, want % X", request, want)
	}
}

func TestPlanUDPReadEmitsRequestAndSIDEchoResponse(t *testing.T) {
	cfg := &FINSConfig{Transport: "udp", SID: 0x01, Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 2 {
		t.Fatalf("packet count = %d, want 2", len(packets))
	}
	if packets[0].L4.Protocol != "udp" || packets[1].L4.Protocol != "udp" {
		t.Fatalf("protocols = %q/%q, want udp/udp", packets[0].L4.Protocol, packets[1].L4.Protocol)
	}
	if packets[0].Payload[9] != 0x01 || packets[1].Payload[9] != 0x01 {
		t.Fatalf("SID was not echoed: request=% X response=% X", packets[0].Payload, packets[1].Payload)
	}
	if !bytes.Equal(packets[1].Payload[12:14], []byte{0x00, 0x00}) {
		t.Fatalf("response code = % X, want 0000", packets[1].Payload[12:14])
	}
	if len(packets[1].Payload) != 18 {
		t.Fatalf("response length = %d, want 18", len(packets[1].Payload))
	}
}

func TestPlanTCPAddsFINSFrameSendHeader(t *testing.T) {
	cfg := &FINSConfig{Transport: "tcp", SID: 1, Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	var data []core.PacketConfig
	for _, packet := range packets {
		if packet.L4.Protocol == "tcp" && packet.L4.Flags&0x08 != 0 && len(packet.Payload) > 0 {
			data = append(data, packet)
		}
	}
	if len(data) < 2 {
		t.Fatalf("data packets = %d, want request and response", len(data))
	}
	for _, packet := range data[:2] {
		if !bytes.Equal(packet.Payload[:4], []byte("FINS")) {
			t.Fatalf("magic = % X, want FINS", packet.Payload[:4])
		}
	}
}

func TestPlanClockReadUsesBCDResponse(t *testing.T) {
	cfg := &FINSConfig{Transport: "udp", SID: 1, Commands: []FINSCommand{{Command: CommandClockRead, Clock: &FINSClock{Century: 20, Year: 26, Month: 8, Day: 18, Hour: 14, Minute: 30, Second: 0, Weekday: 2}}}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	// Wireshark omron-fins dissector (3.6.14 / master) parses a 0x0701 clock-read
	// response as exactly: 2-byte command (0x0701) + 2-byte end code + 7-byte
	// clock (year, month, date, hour, minute, second, weekday). There is NO
	// century byte in the FINS clock response; emitting one makes `offset` never
	// advance and tshark marks the frame malformed.
	want := []byte{0x07, 0x01, 0x00, 0x00, 0x26, 0x08, 0x18, 0x14, 0x30, 0x00, 0x02}
	if !bytes.HasSuffix(packets[1].Payload, want) {
		t.Fatalf("clock response = % X, want BCD suffix % X", packets[1].Payload, want)
	}
}

func boolPtr(v bool) *bool { return &v }

func TestPlanHonorsExpectResponseFalse(t *testing.T) {
	cfg := &FINSConfig{Transport: "udp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 1, ExpectResponse: boolPtr(false)}}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 {
		t.Fatalf("packet count = %d, want 1", len(packets))
	}
}

func TestBuildReadResponseUsesBigEndianWords(t *testing.T) {
	frame, err := BuildFrameWithConfig(&FINSConfig{}, FINSCommand{Command: CommandMemoryAreaRead, Items: 2}, true, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(frame, []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x02}) {
		t.Fatalf("response data = % X", frame)
	}
}

func TestValidateRejectsReadDataLengthMismatch(t *testing.T) {
	cfg := &FINSConfig{Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 2, Data: []byte{1}}}}
	if err := NewPlanner().Validate(testSpec(cfg)); err == nil || !strings.Contains(err.Error(), "data length") {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestPlanHonorsExplicitSIDWhenSIDAutoDisabled(t *testing.T) {
	cfg := &FINSConfig{Transport: "udp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, SID: 5, MemoryArea: "dm", Items: 1}, {Command: CommandMemoryAreaRead, SID: 9, MemoryArea: "dm", Items: 1}}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if packets[0].Payload[9] != 5 || packets[2].Payload[9] != 9 {
		t.Fatalf("request SIDs = %02X/%02X", packets[0].Payload[9], packets[2].Payload[9])
	}
}

func TestPlanKeepsConfiguredSIDWhenSIDAutoDisabled(t *testing.T) {
	cfg := &FINSConfig{Transport: "udp", SID: 7, SIDAutoSet: true, SIDAuto: false, Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}, {Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if packets[0].Payload[9] != 7 || packets[2].Payload[9] != 7 {
		t.Fatalf("request SIDs = %02X/%02X", packets[0].Payload[9], packets[2].Payload[9])
	}
}

func TestPlanHonorsCommandSIDWhenSIDAutoEnabled(t *testing.T) {
	cfg := &FINSConfig{SID: 7, SIDAuto: true, Commands: []FINSCommand{
		{Command: CommandMemoryAreaRead, SID: 99, MemoryArea: "dm", Items: 1},
		{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1},
	}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if got := []byte{packets[0].Payload[9], packets[2].Payload[9]}; !bytes.Equal(got, []byte{99, 8}) {
		t.Fatalf("request SIDs = %02X, want 63 08", got)
	}
}

func TestPlanTCPSequenceAndAcknowledgementSpaces(t *testing.T) {
	cfg := &FINSConfig{Transport: "tcp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	syn, synAck, ack := packets[0], packets[1], packets[2]
	if synAck.L4.Ack != syn.L4.Seq+1 || ack.L4.Seq != syn.L4.Seq+1 || ack.L4.Ack != synAck.L4.Seq+1 {
		t.Fatalf("invalid handshake sequence")
	}
}

func TestJSONConfigDefaultsSIDAutoAndHonorsExplicitFalse(t *testing.T) {
	cases := []struct {
		name string
		json string
		want []byte
	}{
		{
			name: "default enabled",
			json: `{"transport":"udp","sid":7,"commands":[{"command":257,"memory_area":"dm","items":1},{"command":257,"memory_area":"dm","items":1}]}`,
			want: []byte{7, 8},
		},
		{
			name: "explicit disabled",
			json: `{"transport":"udp","sid":7,"sid_auto":false,"commands":[{"command":257,"memory_area":"dm","items":1},{"command":257,"memory_area":"dm","items":1}]}`,
			want: []byte{7, 7},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg FINSConfig
			if err := json.Unmarshal([]byte(tc.json), &cfg); err != nil {
				t.Fatal(err)
			}
			packets, err := collectPlan(t, NewPlanner(), testSpec(&cfg))
			if err != nil {
				t.Fatal(err)
			}
			if got := []byte{packets[0].Payload[9], packets[2].Payload[9]}; !bytes.Equal(got, tc.want) {
				t.Fatalf("request SIDs = %02X, want %02X", got, tc.want)
			}
		})
	}
}

func TestValidateRejectsEmptyMemoryAreaWriteData(t *testing.T) {
	for _, bit := range []uint8{0, 1} {
		t.Run(fmt.Sprintf("bit-%d", bit), func(t *testing.T) {
			cfg := &FINSConfig{Commands: []FINSCommand{{Command: CommandMemoryAreaWrite, MemoryArea: "dm", Bit: bit, Items: 1}}}
			if bit != 0 {
				cfg.Commands[0].MemoryArea = "hr"
			}
			if err := NewPlanner().Validate(testSpec(cfg)); err == nil || !strings.Contains(err.Error(), "data length") {
				t.Fatalf("Validate() = %v, want empty write data rejection", err)
			}
		})
	}
}

func TestPlanHonorsDownDirectionWithoutAutomaticResponse(t *testing.T) {
	cfg := &FINSConfig{Commands: []FINSCommand{{Command: CommandMemoryAreaRead, Direction: "down", MemoryArea: "dm", Items: 1}}}
	packets, err := collectPlan(t, NewPlanner(), testSpec(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 || packets[0].Direction != "down" || packets[0].Payload[0] != 0xC1 {
		t.Fatalf("packets = %#v, want one down response frame", packets)
	}
}

func TestPlanRejectsInvalidHeaderFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  FINSConfig
	}{
		{name: "icf", cfg: FINSConfig{ICF: 0x01}},
		{name: "gct", cfg: FINSConfig{GCT: 0x03}},
		{name: "dna", cfg: FINSConfig{DNA: 1}},
		{name: "sna", cfg: FINSConfig{SNA: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Commands = []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1}}
			if err := NewPlanner().Validate(testSpec(&tc.cfg)); err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("Validate() = %v, want %s validation error", err, tc.name)
			}
		})
	}
}

func TestValidateRejectsDirectionSpecificICF(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response bool
		icf      uint8
	}{
		{name: "request response bit", icf: 0xC1},
		{name: "response command bit", response: true, icf: 0x81},
		{name: "request no response", icf: 0x81 | 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := FINSCommand{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 1, ICF: tc.icf}
			if tc.response {
				cmd.Direction = "down"
			}
			if err := NewPlanner().Validate(testSpec(&FINSConfig{Commands: []FINSCommand{cmd}})); err == nil || !strings.Contains(err.Error(), "icf") {
				t.Fatalf("Validate() = %v, want direction-specific icf rejection", err)
			}
		})
	}
}

func TestPlanSupportsMemoryAreaBitZero(t *testing.T) {
	var cfg FINSConfig
	if err := json.Unmarshal([]byte(`{"commands":[{"command":257,"memory_area":"hr","bit":0,"items":2}]}`), &cfg); err != nil {
		t.Fatal(err)
	}
	frame, err := BuildFrameWithConfig(&cfg, cfg.Commands[0], false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if frame[12] != 0x32 || frame[15] != 0 || frame[16] != 0 || frame[17] != 2 {
		t.Fatalf("bit-zero frame = % X, want HR bit area and NC=2", frame)
	}
}

func TestValidateRejectsMemoryAreaBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  FINSCommand
	}{
		{name: "address", cmd: FINSCommand{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 32768, Items: 1}},
		{name: "word items", cmd: FINSCommand{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 961}},
		{name: "bit items", cmd: FINSCommand{Command: CommandMemoryAreaRead, MemoryArea: "hr", Bit: 1, Items: 4097}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := NewPlanner().Validate(testSpec(&FINSConfig{Commands: []FINSCommand{tc.cmd}})); err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("Validate() = %v, want %s bounds rejection", err, tc.name)
			}
		})
	}
}

func TestValidateRejectsInvalidClockBCDFields(t *testing.T) {
	cfg := &FINSConfig{Commands: []FINSCommand{{Command: CommandClockRead, Clock: &FINSClock{Century: 20, Year: 26, Month: 13, Day: 18, Hour: 14, Minute: 30, Second: 0, Weekday: 2}}}}
	if err := NewPlanner().Validate(testSpec(cfg)); err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("Validate() = %v, want clock range rejection", err)
	}
}

func TestPlanRejectsInvalidItemsAndBit(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  FINSCommand
		want string
	}{
		{name: "zero items", cmd: FINSCommand{Command: CommandMemoryAreaRead, MemoryArea: "dm", Items: 0}, want: "items"},
		{name: "bit out of range", cmd: FINSCommand{Command: CommandMemoryAreaRead, MemoryArea: "hr", Bit: 16, Items: 1}, want: "bit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := NewPlanner().Validate(testSpec(&FINSConfig{Commands: []FINSCommand{tc.cmd}})); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
}

func collectPlan(t *testing.T, planner *Planner, spec core.FlowSpec) ([]core.PacketConfig, error) {
	t.Helper()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		return nil, err
	}
	var packets []core.PacketConfig
	for packet := range ch {
		packets = append(packets, packet)
	}
	return packets, nil
}

func TestEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config（无 Metadata fins）默认化（udp + dm read），
	// Validate/Plan/Generate 均产默认流。
	if err := NewPlanner().Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000}); err != nil {
		t.Fatalf("empty config Validate err: %v", err)
	}
	ch, err := NewPlanner().Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000})
	if err != nil {
		t.Fatalf("empty config Plan err: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n == 0 {
		t.Fatal("empty config produced 0 packets")
	}

	var events []layers.MessageEvent
	err = (&FINSGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatalf("empty config Generate err: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config generated 0 events")
	}
}
