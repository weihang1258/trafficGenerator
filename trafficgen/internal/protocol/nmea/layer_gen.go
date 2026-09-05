// Package nmea implements the NMEA 0183 sentence terminal layer
// （海用电子设备数据交换标准，[tcp→nmea]/[udp→nmea] 双载体）：明文 ASCII
// 句子 `$`+地址(2 talker+3 type)+逗号字段+[`*`两位大写 hex XOR 校验和]+
// CRLF。单向通知流（恒上行，无响应）；TCP 字节流按 pack/split 切段，UDP
// 数据报按事件组报文。
//
// Wire-format authority: docs/protocol-designs/69-nmea-design.md v2.0.0
// §3 (talker 值域表/七句型逐字段/XOR 口径/82B 上界）与 testcase §3 字节
// 基线表（全句 hex 含 CRLF 尾 0d0a、XOR 复算值）。本机无 NMEA dissector，
// 全部断言走 tcp.payload/udp.payload + frames offset 54/74/42/62。
package nmea

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// NMEAGenerator is the nmea terminal-layer generator
// ([tcp→nmea]/[udp→nmea])。Each sentence event becomes one MessageEvent
// carrying the COMPLETE sentence bytes (ASCII + CRLF)；pack_next / Pack
// 合并为单事件多句（tcp 层单段），SplitAt 驱动跨段切位（tcp 层 MSS/切分）。
// UDP 载体下每会话每事件独立成报文（报文边界不切句），pack 时同会话多句
// 拼接一报文。
type NMEAGenerator struct{}

// Name returns "nmea".
func (g *NMEAGenerator) Name() string { return "nmea" }

// sessionRun is the per-session generation state (design §5：单向流，唯一
// 句间关联 = GSV 序列 total/msg_num)。
type sessionRun struct {
	sess core.NMEASession
	// gsvTotal/msgNum track the open GSV sequence for msg_num 连续性
	// （validator 已校验，生成器只做防御性一致：不同 total 即新序列）。
	gsvTotal string
	gsvNext  int
	pending  []byte
	hasPend  bool
}

// Generate walks the sessions' events and emits one MessageEvent per
// sentence (or per packed run)。Sequential mode walks session by session；
// concurrent mode interleaves round-robin by event index (设计 §5 并发会话）。
func (g *NMEAGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("nmea generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.NMEA
	if cfg == nil {
		cfg = &core.NMEAConfig{}
	}
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		// 空配置默认流（P0b）：GGA 基线单句（fixture 基线值）。TCP 9 包
		// （3 握手 + 1 句 + 4 挥手）；UDP 1 报文。
		sessions = []core.NMEASession{{
			Events: []core.NMEAEvent{{
				Kind:   "sentence",
				Talker: "GP",
				Type:   "GGA",
				Fields: FixtureGGABaseline(),
			}},
		}}
	}

	runs := make([]*sessionRun, len(sessions))
	for i, s := range sessions {
		cp := s
		runs[i] = &sessionRun{sess: cp}
	}

	emit := func(run *sessionRun, b []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		out := layers.MessageEvent{Up: true, Bytes: b}
		if p := run.sess.SrcPort; p != 0 {
			out.SrcPort = p
		}
		return req.EmitMsg(out)
	}

	flush := func(run *sessionRun) error {
		if !run.hasPend {
			return nil
		}
		b := run.pending
		run.pending = nil
		run.hasPend = false
		return emit(run, b)
	}

	buildOne := func(run *sessionRun, ev core.NMEAEvent) error {
		line, err := BuildSentence(run, ev)
		if err != nil {
			return err
		}
		run.pending = append(run.pending, line...)
		run.hasPend = true
		pack := ev.PackNext || cfg.Pack
		if !pack {
			return flush(run)
		}
		return nil
	}

	if cfg.Concurrent {
		maxLen := 0
		for _, r := range runs {
			if len(r.sess.Events) > maxLen {
				maxLen = len(r.sess.Events)
			}
		}
		for j := 0; j < maxLen; j++ {
			for _, r := range runs {
				if j >= len(r.sess.Events) {
					continue
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				if err := buildOne(r, r.sess.Events[j]); err != nil {
					return err
				}
			}
		}
	} else {
		for _, r := range runs {
			for _, ev := range r.sess.Events {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				if err := buildOne(r, ev); err != nil {
					return err
				}
			}
		}
	}
	for i, r := range runs {
		if r.hasPend {
			// pack 尾巴：pack 语义是"与下一句合并"，末尾无下一句时直接
			// 冲刷为独立段（不报错——与 ethmining pack_next 尾错不同，
			// NMEA 的 Pack 是会话级开关，末句无后继是合法形态）。
			_ = i
			if err := flush(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer.
func (g *NMEAGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *NMEAGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("nmea generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("nmea", func() (layers.LayerGenerator, error) {
		return &NMEAGenerator{}, nil
	})
	layers.RegisterLayerValidator("nmea", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
