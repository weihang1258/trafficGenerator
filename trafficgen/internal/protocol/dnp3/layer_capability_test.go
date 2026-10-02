package dnp3

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// 设计 95-dnp3 §7 N-21：层链拒绝 transport=udp，锚词须在 layer validator
// （ValidateSpec 期）到达 task error——生成器期报错被 0-packet 掩蔽。
func TestLayerValidator_UDPRejected(t *testing.T) {
	p, err := layers.BuildLayersPlanner("dnp3", []byte(`[
		{"ip": {"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{"tcp": {}},
		{"dnp3": {"transport": "udp", "scenario": "reset_link"}}
	]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	err = p.Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 20000})
	if err == nil || !strings.Contains(err.Error(), "transport=udp is not supported on the layer chain") {
		t.Fatalf("err = %v, want udp anchor", err)
	}
}

// 设计 95-dnp3 §7 N-22：层链拒绝 multi_outstation（锚词同上）。
func TestLayerValidator_MultiOutstationRejected(t *testing.T) {
	p, err := layers.BuildLayersPlanner("dnp3", []byte(`[
		{"ip": {"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{"tcp": {}},
		{"dnp3": {"multi_outstation": {"outstation_count": 3, "outstation_ip_list": ["10.0.0.2", "10.0.0.3", "10.0.0.4"], "src_port_start": 20001}}}
	]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	err = p.Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 20000})
	if err == nil || !strings.Contains(err.Error(), "multi_outstation is not supported on the layer chain") {
		t.Fatalf("err = %v, want multi_outstation anchor", err)
	}
}

// t41: link_fcv/link_fcb 在册后 reset 帧控制字节 = DIR|PRM（FCV=0 → 线上
// FCB=0）。经生成器全链路断言（0xC0 @ 控制字节位）。
func TestScenario_ResetLinkFCVZero(t *testing.T) {
	events := collectEvents(t, basicSpec(&core.DNP3Config{
		Scenario: "reset_link", LinkFCB: 1, LinkFCV: ptrUint8(0),
	}))
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if got := events[0].Bytes[3]; got != 0xC0 {
		t.Fatalf("reset control = %02X, want C0", got)
	}
}

// t42: read_class0 + FCB=1 FCV=1 → request 帧 FCB/FCV 位置 1（0xF3），
// respond 帧 0x03。FCV 缺省 = 现行为（request 恒 FCV=1）。
func TestScenario_ReadClass0FCVToggle(t *testing.T) {
	events := collectEvents(t, basicSpec(&core.DNP3Config{
		Scenario: "read_class0", LinkFCB: 1, LinkFCV: ptrUint8(1),
		Objects: []core.DNP3Object{{ObjectType: 60, Variation: 1, Qualifier: 6}},
	}))
	// reset(2) + request(1) + ack(1) + respond(1) + ack(1)
	if len(events) < 6 {
		t.Fatalf("events = %d, want >=6", len(events))
	}
	if got := events[2].Bytes[3]; got != 0xF3 {
		t.Fatalf("request control = %02X, want F3", got)
	}
	if got := events[4].Bytes[3]; got != 0x03 {
		t.Fatalf("respond control = %02X, want 03", got)
	}
}

// t14: user_data_size=16 → 用户数据补齐 16B，单块 CRC（帧长 10+16+2=28，
// LEN 字节 = 18）。
func TestScenario_UserDataSize16(t *testing.T) {
	sz := uint16(16)
	events := collectEvents(t, basicSpec(&core.DNP3Config{
		Scenario: "read_class0", UserDataSize: &sz,
		Objects: []core.DNP3Object{{ObjectType: 60, Variation: 1, Qualifier: 6}},
	}))
	req := events[2].Bytes
	if len(req) != 28 {
		t.Fatalf("request frame len = %d, want 28", len(req))
	}
	if req[2] != 18 {
		t.Fatalf("LEN = %d, want 18 (16 user data + 2 CRC)", req[2])
	}
}

// t15 形：user_data_size=17 → 跨块（16+1），LEN = 17+2*2=21 → 帧长 10+17+4=31。
func TestScenario_UserDataSize17CrossBlock(t *testing.T) {
	sz := uint16(17)
	events := collectEvents(t, basicSpec(&core.DNP3Config{
		Scenario: "read_class0", UserDataSize: &sz,
		Objects: []core.DNP3Object{{ObjectType: 60, Variation: 1, Qualifier: 6}},
	}))
	req := events[2].Bytes
	if len(req) != 31 {
		t.Fatalf("request frame len = %d, want 31", len(req))
	}
}

func ptrUint8(v uint8) *uint8 { return &v }
