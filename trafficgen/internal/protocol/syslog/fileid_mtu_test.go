package syslog

// D-UDP-MTU：file_source 在 validator（校验时 Msg 为空）之后才加载，
// RFC 5426 §6 的 65507 上限必须在 Generate 加载后复查——syslog 报文是
// 结构整体不可拆，超限只能拒。测试登记 T-UDP-MTU-10。

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// 【MCP 可触发】syslog + 超大 Msg（等价于 file_source 加载结果）→ Generate
// 报错含 65507 锚词（当前实现任务完成产出回绕坏包，红）。
func TestSyslogGenerate_MsgOverHardMaxRejected(t *testing.T) {
	g := &SyslogGenerator{}
	req := &layers.GenRequest{
		Layer: layers.Layer{Name: "syslog", Config: map[string]interface{}{}},
		Sess:  &layers.SessionState{},
		Meta: layers.FlowMeta{
			Syslog: &core.SyslogConfig{Msg: strings.Repeat("a", 70000)},
		},
	}
	err := g.Generate(t.Context(), req)
	if err == nil {
		t.Fatal("70000B Msg over udp: Generate() = nil error, want 65507 guard (previously silent wrap)")
	}
	if !strings.Contains(err.Error(), "65507") {
		t.Fatalf("err = %v, want anchor 65507", err)
	}
}

// 上限恰好合法：65507B Msg 必须正常出事件。
func TestSyslogGenerate_MsgAtHardMaxEmits(t *testing.T) {
	g := &SyslogGenerator{}
	var evs []layers.MessageEvent
	req := &layers.GenRequest{
		Layer:   layers.Layer{Name: "syslog", Config: map[string]interface{}{}},
		Sess:    &layers.SessionState{},
		EmitMsg: func(ev layers.MessageEvent) error { evs = append(evs, ev); return nil },
		Meta: layers.FlowMeta{
			Syslog: &core.SyslogConfig{Msg: strings.Repeat("a", MaxUDPPayloadBytes)},
		},
	}
	if err := g.Generate(t.Context(), req); err != nil {
		t.Fatalf("65507B Msg (legal max): Generate() error = %v", err)
	}
	if len(evs) == 0 {
		t.Fatal("65507B Msg: no events emitted")
	}
}
