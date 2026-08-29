package igmp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type IGMPGenerator struct{}

func (g *IGMPGenerator) Name() string                     { return "igmp" }
func (g *IGMPGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits IGMP full packets via req.Emit (raw-IP [ip, igmp] chain). The
// ChainPlanner's raw-IP branch fills L2/DSCP/TTL; here we set L3.SrcIP/DstIP,
// L3.Protocol, Direction, and Payload.
func (g *IGMPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("igmp generator: Emit is nil")
	}
	cfg := req.Meta.IGMP
	if cfg == nil {
		// P0b-2: empty config → default v1 general query.
		cfg = &core.IGMPConfig{Profile: "v1", Kind: "query", Group: "0.0.0.0"}
	}
	if err := (Planner{}).Validate(core.FlowSpec{IGMP: cfg, SrcIP: req.Meta.SrcIP, DstIP: req.Meta.DstIP, TTL: req.Meta.TTL}); err != nil {
		return err
	}
	src := req.Meta.SrcIP
	emit := func(group string, msg []byte) error {
		pkt := core.PacketConfig{
			FlowID:    "igmp",
			Direction: "up",
			L3: core.L3Config{
				SrcIP:    src,
				DstIP:    group,
				Protocol: core.ProtocolIGMP,
				TTL:      1,
			},
			L4:      core.L4Config{Protocol: "igmp"},
			Payload: msg,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return req.Emit(pkt)
		}
	}

	// Event sequence (multi-message).
	if len(cfg.Events) > 0 {
		for i, ev := range cfg.Events {
			msg, err := buildIGMPMessage(ev.Profile, ev.Kind, ev.Group,
				ev.MaxResponseTime, ev.MaxResponseCode, ev.SFlag, ev.QRV, ev.QQIC,
				ev.Records, ev.Sources, ev.ChecksumMode)
			if err != nil {
				return fmt.Errorf("igmp: events[%d] %v", i, err)
			}
			if err := emit(ev.Group, msg); err != nil {
				return err
			}
		}
		return nil
	}

	// Single message.
	profile := cfg.Profile
	if profile == "" {
		profile = "v1"
	}
	kind := cfg.Kind
	if kind == "" {
		kind = "query"
	}
	group := cfg.Group
	if group == "" {
		group = "0.0.0.0"
	}
	msg, err := buildIGMPMessage(profile, kind, group,
		cfg.MaxResponseTime, cfg.MaxResponseCode, cfg.SFlag, cfg.QRV, cfg.QQIC,
		cfg.Records, cfg.Sources, cfg.ChecksumMode)
	if err != nil {
		return err
	}
	return emit(group, msg)
}

func init() {
	layers.RegisterLayerGenerator("igmp", func() (layers.LayerGenerator, error) { return &IGMPGenerator{}, nil })
	layers.RegisterLayerValidator("igmp", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
