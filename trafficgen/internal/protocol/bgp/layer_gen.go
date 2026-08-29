package bgp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type BGPGenerator struct{}

func (*BGPGenerator) Name() string { return "bgp" }

func (g *BGPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("bgp generator: EmitMsg is nil")
	}
	cfg := req.Meta.BGP
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（layers 数组路径层 config 为空/缺省时）。
		// 与 Planner.Plan 的默认化一致。
		cfg = &BGPConfig{}
	}
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	if err := validateSessionConfig(cfg); err != nil {
		return err
	}
	// 多会话展开（P0a 模式，同 postgresql/tns/mongodb）：每条 session 一条
	// 独立 TCP 连接，session 源端口带上事件，tcp 层据 SrcPort 判定会话边界
	// （挥旧握新）。sessions==1 时提升该 session 的 events（既有契约：单
	// session 事件不被静默丢弃）。
	if len(cfg.Sessions) > 1 {
		for _, s := range cfg.Sessions {
			if err := emitEvents(ctx, cfg, s.Events, s.SrcPort, req); err != nil {
				return err
			}
		}
		return nil
	}
	events := cfg.Events
	if len(cfg.Sessions) == 1 {
		events = cfg.Sessions[0].Events
	}
	return emitEvents(ctx, cfg, events, 0, req)
}

// emitEvents encodes and emits one event list; srcPort is the session's TCP
// source port override (0 = default flow port).
func emitEvents(ctx context.Context, cfg *BGPConfig, events []core.BGPEvent, srcPort uint16, req *layers.GenRequest) error {
	if events == nil {
		// P0b-2：events 字段缺省(nil)时产默认流（open→open→ka→ka→ka→ka，
		// 与既有默认化契约一致）；显式 `events: []` 表示 connect-only 会话。
		events = defaultDualEvents(cfg)
	}
	emit := func(up bool, b []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return req.EmitMsg(layers.MessageEvent{Up: up, Bytes: b, SrcPort: srcPort})
		}
	}
	for i := range events {
		ev := &events[i]
		msg, err := BuildEvent(*ev)
		if err != nil {
			return err
		}
		up := ev.Direction != "s2c" // c2s / 缺省 → 上行；s2c → 下行
		if err := emit(up, msg); err != nil {
			return err
		}
	}
	return nil
}

// defaultDualEvents is the P0b-2 default session emitted when the events field
// is absent. It mirrors the historic 6-message default (two opens followed by
// two keepalive pairs) so the existing empty-config contract is unchanged. The
// opens inherit any top-level version/my_as/hold_time/identifier values so a
// config like {HoldTime:90} still yields holdtime 90 in the default opens.
func defaultDualEvents(cfg *BGPConfig) []core.BGPEvent {
	inherits := func(c *BGPConfig) (uint8, uint32, uint16, string) {
		v := normalized(c)
		return v.Version, v.ASN, v.HoldTime, v.Identifier
	}
	ver, asn, hold, ident := inherits(cfg)
	return []core.BGPEvent{
		{Kind: "open", Direction: "c2s", Version: ver, MyAS: asn, HoldTime: hold, Identifier: ident},
		{Kind: "open", Direction: "s2c", Version: ver, MyAS: asn, HoldTime: hold, Identifier: ident},
		{Kind: "keepalive", Direction: "c2s"},
		{Kind: "keepalive", Direction: "s2c"},
		{Kind: "keepalive", Direction: "c2s"},
		{Kind: "keepalive", Direction: "s2c"},
	}
}

func (*BGPGenerator) GenEvents() layers.EventGenerator { return &BGPGenerator{} }
func (*BGPGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("bgp generator: EmitEvent is not wired")
}

func init() {
	layers.RegisterLayerGenerator("bgp", func() (layers.LayerGenerator, error) { return &BGPGenerator{}, nil })
	layers.RegisterLayerValidator("bgp", func(spec *core.FlowSpec) error { return (Planner{}).Validate(*spec) })
}
