package socks5

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// SOCKS5 终结层生成器测试（J 组组合层）——事件模式（pop3/imap layer_gen
// 同款）：字节由 legacy build* 纯函数产出，TCP 语义交给 tcp 层生成器；
// 链路径限制（UDP relay / FileSource 数据）必须显式拒绝。

func mustPlanChain(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	g := &SOCKS5Generator{}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	err := g.Generate(context.Background(), &layers.GenRequest{
		EmitMsg: emit,
		Meta:    layers.FlowMeta{Socks: spec.Socks},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return events
}

// TestSocks5Chain_SignalingEventOrder: 默认配置（socks5 no_auth connect）的
// 信令事件序列 greeting → method → request → reply，方向与字节与 legacy
// build* 一致（RFC 1928 §3/§4/§6）。
func TestSocks5Chain_SignalingEventOrder(t *testing.T) {
	events := mustPlanChain(t, core.FlowSpec{Socks: &core.SocksConfig{}})
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4 (greeting/method/request/reply)", len(events))
	}
	wantDirs := []bool{true, false, true, false}
	wantBytes := [][]byte{
		{0x05, 0x01, 0x00},                                        // greeting no_auth
		{0x05, 0x00},                                              // method response
		{0x05, 0x01, 0x00, 0x03, 15},                              // request: ver/cmd/rsv/atyp=len-prefixed domain
		{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0},                // reply rep=0 bnd 0.0.0.0:0
	}
	for i, ev := range events {
		if ev.Up != wantDirs[i] {
			t.Errorf("event %d dir up=%v, want %v", i, ev.Up, wantDirs[i])
		}
		got := ev.Bytes
		if i == 2 {
			// request 剩余部分是默认域名 + 端口 80，前 5 字节先比对。
			for j, b := range wantBytes[i] {
				if got[j] != b {
					t.Errorf("event %d byte %d = %#x, want %#x", i, j, got[j], b)
				}
			}
			continue
		}
		if len(got) != len(wantBytes[i]) {
			t.Fatalf("event %d len = %d, want %d (%v)", i, len(got), len(wantBytes[i]), got)
		}
		for j, b := range wantBytes[i] {
			if got[j] != b {
				t.Errorf("event %d byte %d = %#x, want %#x", i, j, got[j], b)
			}
		}
	}
}

// TestSocks5Chain_PasswordAuth: password 认证事件 6 个，auth 请求字节含
// 默认 user/pass（legacy buildAuthRequest 默认化）。
func TestSocks5Chain_PasswordAuth(t *testing.T) {
	events := mustPlanChain(t, core.FlowSpec{Socks: &core.SocksConfig{AuthMethod: "password"}})
	if len(events) != 6 {
		t.Fatalf("got %d events, want 6 (+auth req/resp)", len(events))
	}
	authReq := events[2].Bytes
	// `01 04 user 04 pass`
	want := []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'}
	if string(authReq) != string(want) {
		t.Errorf("auth request = %v, want %v", authReq, want)
	}
	if !events[2].Up || events[3].Up {
		t.Errorf("auth directions wrong: req up=%v resp up=%v", events[2].Up, events[3].Up)
	}
}

// TestSocks5Chain_DataPlane: Rep=0 时 Data 消息按序上包（方向按
// direction 字段），Rep!=0 抑制数据面（RFC 1928 失败即关连）。
func TestSocks5Chain_DataPlane(t *testing.T) {
	events := mustPlanChain(t, core.FlowSpec{Socks: &core.SocksConfig{
		Data: []core.SocksDataMessage{
			{Direction: "up", Payload: "GET / HTTP/1.0\r\n\r\n"},
			{Direction: "down", Payload: "HTTP/1.0 200 OK\r\n\r\n"},
		},
	}})
	if len(events) != 6 {
		t.Fatalf("got %d events, want 6 (4 signaling + 2 data)", len(events))
	}
	if string(events[4].Bytes) != "GET / HTTP/1.0\r\n\r\n" || !events[4].Up {
		t.Errorf("data[0] = %q up=%v, want GET up", events[4].Bytes, events[4].Up)
	}
	if string(events[5].Bytes) != "HTTP/1.0 200 OK\r\n\r\n" || events[5].Up {
		t.Errorf("data[1] = %q up=%v, want 200 down", events[5].Bytes, events[5].Up)
	}

	events = mustPlanChain(t, core.FlowSpec{Socks: &core.SocksConfig{
		Rep: 1,
		Data: []core.SocksDataMessage{{Payload: "x"}},
	}})
	if len(events) != 4 {
		t.Fatalf("rep=1: got %d events, want 4 (data suppressed)", len(events))
	}
}

// TestSocks5Chain_Socks4: SOCKS4 两阶段信令。
func TestSocks5Chain_Socks4(t *testing.T) {
	events := mustPlanChain(t, core.FlowSpec{Socks: &core.SocksConfig{Version: "socks4"}})
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (socks4 request/reply)", len(events))
	}
	req := events[0].Bytes
	if req[0] != 0x04 || req[1] != 0x01 {
		t.Errorf("socks4 request ver/cmd = %#x/%#x, want 04/01", req[0], req[1])
	}
	if !events[0].Up || events[1].Up {
		t.Errorf("socks4 directions wrong")
	}
}

// TestSocks5Chain_RejectsUDPRelayAndFileSource: 链路径限制显式拒绝——
// UDP relay 需第二个 4-tuple、FileSource 需 engine 级缓存，事件模型不承载。
func TestSocks5Chain_RejectsUDPRelayAndFileSource(t *testing.T) {
	g := &SOCKS5Generator{}
	err := g.Generate(context.Background(), &layers.GenRequest{
		EmitMsg: func(layers.MessageEvent) error { return nil },
		Meta:    layers.FlowMeta{Socks: &core.SocksConfig{UDP: &core.Socks5UDP{}}},
	})
	if err == nil {
		t.Error("UDP relay config must be rejected on layer chains")
	}
	err = g.Generate(context.Background(), &layers.GenRequest{
		EmitMsg: func(layers.MessageEvent) error { return nil },
		Meta: layers.FlowMeta{Socks: &core.SocksConfig{Data: []core.SocksDataMessage{
			{FileSource: &filesystem.FileSource{}},
		}}},
	})
	if err == nil {
		t.Error("FileSource data must be rejected on layer chains")
	}
}

// TestSocks5LayerValidator_CalibratesTCP: 层 validator 校准 spec.TCP
// 握手/挥手 true（legacy 恒产，tcp 层生成器必须补上）；链路径限制
// （UDP relay / FileSource）validator 先行拒绝（生成器错误会被链上
// "驱动失败 → 空流"契约吞掉，validator 拒绝为双保险）。
func TestSocks5LayerValidator_CalibratesTCP(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Socks: &core.SocksConfig{}}
	if err := (&Planner{}).Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestSocks5LayerValidator_RejectsUDPRelayAndFileSource(t *testing.T) {
	validate := func(spec core.FlowSpec) error {
		p, err := layers.BuildLayersPlanner("socks5", []byte(`[{"socks5":{}}]`))
		if err != nil {
			return err
		}
		return p.Validate(spec)
	}
	err := validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		Socks: &core.SocksConfig{UDP: &core.Socks5UDP{}}})
	if err == nil {
		t.Error("validator must reject UDP relay on layer chains")
	}
	err = validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		Socks: &core.SocksConfig{Data: []core.SocksDataMessage{{FileSource: &filesystem.FileSource{}}}}})
	if err == nil {
		t.Error("validator must reject FileSource data on layer chains")
	}
}
