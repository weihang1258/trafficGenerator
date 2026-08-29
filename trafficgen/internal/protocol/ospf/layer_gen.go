package ospf

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type OSPFGenerator struct{}

func (g *OSPFGenerator) Name() string                     { return "ospf" }
func (g *OSPFGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits OSPFv2 full packets via req.Emit (raw-IP [ip, ospf] chain).
// The ChainPlanner's raw-IP branch fills L2/DSCP/TTL; here we set
// L3.SrcIP/DstIP, L3.Protocol, Direction, and Payload.
func (g *OSPFGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("ospf generator: Emit is nil")
	}
	cfg := req.Meta.OSPF
	if cfg == nil {
		// P0b-2: empty config → default hello.
		cfg = &core.OSPFConfig{Version: 2, PacketType: "hello", RouterID: "1.1.1.1", AreaID: "0.0.0.0"}
	}
	if err := (Planner{}).Validate(core.FlowSpec{OSPF: cfg}); err != nil {
		return err
	}
	src := req.Meta.SrcIP
	defaultDst := "224.0.0.5" // all ospf routers
	emit := func(msg []byte, dst string) error {
		if dst == "" {
			dst = defaultDst
		}
		pkt := core.PacketConfig{
			FlowID:    "ospf",
			Direction: "up",
			L3: core.L3Config{
				SrcIP:    src,
				DstIP:    dst,
				Protocol: core.ProtocolOSPF,
				TTL:      1,
			},
			L4:      core.L4Config{Protocol: "ospf"},
			Payload: msg,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return req.Emit(pkt)
		}
	}

	// Event sequence (adjacency state machine).
	if len(cfg.Events) > 0 {
		for i, ev := range cfg.Events {
			cfg2 := &core.OSPFConfig{
				Version: cfg.Version, RouterID: ev.RouterID, AreaID: ev.AreaID,
				AuthType: cfg.AuthType, ChecksumMode: cfg.ChecksumMode,
			}
			if cfg2.RouterID == "" {
				cfg2.RouterID = cfg.RouterID
			}
			if cfg2.AreaID == "" {
				cfg2.AreaID = cfg.AreaID
			}
			msg, err := buildFromEvent(cfg2, &ev)
			if err != nil {
				return fmt.Errorf("ospf: events[%d] %v", i, err)
			}
			dir := ev.Direction
			up := dir != "s2c"
			// get dst (neighbor or multicast)
			dst := multiDstFor(&ev)
			pkt := core.PacketConfig{
				FlowID: "ospf", Direction: dirName(up),
				L3: core.L3Config{SrcIP: src, DstIP: dst, Protocol: core.ProtocolOSPF, TTL: 1},
				L4: core.L4Config{Protocol: "ospf"}, Payload: msg,
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				if err := req.Emit(pkt); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// Single message from top-level config.
	msg, err := buildFromConfig(cfg)
	if err != nil {
		return err
	}
	dst := req.Meta.DstIP
	if dst == "" {
		dst = defaultDst
	}
	return emit(msg, dst)
}

// buildFromConfig builds one OSPF packet from a flat config.
func buildFromConfig(cfg *core.OSPFConfig) ([]byte, error) {
	mt, err := packetTypeFromString(cfg.PacketType)
	if err != nil {
		return nil, err
	}
	body, err := buildBody(cfg)
	if err != nil {
		return nil, err
	}
	return buildMessage(mt, cfg.RouterID, cfg.AreaID, cfg.AuthType, body, cfg.ChecksumMode)
}

// buildBody builds the per-message body for a flat config.
func buildBody(cfg *core.OSPFConfig) ([]byte, error) {
	mt, _ := packetTypeFromString(cfg.PacketType)
	switch mt {
	case TypeHello:
		mask := cfg.NetworkMask
		if mask == "" {
			mask = "0.0.0.0"
		}
		dr := cfg.DesignatedRouter
		if dr == "" {
			dr = "0.0.0.0"
		}
		bdr := cfg.BackupDesignatedRouter
		if bdr == "" {
			bdr = "0.0.0.0"
		}
		return buildHelloBody(mask, cfg.HelloInterval, cfg.Options, cfg.Priority, cfg.DeadInterval, dr, bdr, cfg.Neighbors), nil
	case TypeDBDescription:
		return buildDDBody(cfg.InterfaceMTU, cfg.Options, cfg.Flags, cfg.DDSequence, cfg.LSAHeaders)
	case TypeLinkStateRequest:
		return buildLSRBody(cfg.Requests), nil
	case TypeLinkStateUpdate:
		var b []byte
		var cnt [4]byte
		binary.BigEndian.PutUint32(cnt[:], uint32(len(cfg.LSAs)))
		b = append(b, cnt[:]...)
		for _, lsa := range cfg.LSAs {
			lb, err := buildLSABody(lsa)
			if err != nil {
				return nil, err
			}
			b = append(b, lb...)
		}
		return b, nil
	case TypeLinkStateAcknowledgment:
		var b []byte
		for _, lh := range cfg.LSAHeaders {
			lb, err := buildLSAHeaderBytes(lh)
			if err != nil {
				return nil, err
			}
			b = append(b, lb...)
		}
		return b, nil
	}
	return nil, fmt.Errorf("ospf: unsupported packet_type %q", cfg.PacketType)
}

// buildFromEvent builds one OSPF packet from an event.
func buildFromEvent(cfg *core.OSPFConfig, ev *core.OSPFEvent) ([]byte, error) {
	mt, err := kindToType(ev.Kind)
	if err != nil {
		return nil, err
	}
	var body []byte
	switch mt {
	case TypeHello:
		mask := ev.NetworkMask
		if mask == "" {
			mask = "0.0.0.0"
		}
		dr := ev.DesignatedRouter
		if dr == "" {
			dr = "0.0.0.0"
		}
		bdr := ev.BackupDesignatedRouter
		if bdr == "" {
			bdr = "0.0.0.0"
		}
		body = buildHelloBody(mask, ev.HelloInterval, ev.Options, ev.Priority, ev.DeadInterval, dr, bdr, ev.Neighbors)
	case TypeDBDescription:
		body, err = buildDDBody(ev.InterfaceMTU, ev.Options, ev.Flags, ev.DDSequence, ev.LSAHeaders)
	case TypeLinkStateRequest:
		body = buildLSRBody(ev.Requests)
	case TypeLinkStateUpdate:
		var b []byte
		var cnt [4]byte
		binary.BigEndian.PutUint32(cnt[:], uint32(len(ev.LSAs)))
		b = append(b, cnt[:]...)
		for _, lsa := range ev.LSAs {
			lb, err := buildLSABody(lsa)
			if err != nil {
				return nil, err
			}
			b = append(b, lb...)
		}
		body = b
	case TypeLinkStateAcknowledgment:
		var b []byte
		for _, lh := range ev.LSAHeaders {
			lb, err := buildLSAHeaderBytes(lh)
			if err != nil {
				return nil, err
			}
			b = append(b, lb...)
		}
		body = b
	default:
		return nil, fmt.Errorf("ospf: unsupported event kind %q", ev.Kind)
	}
	if err != nil {
		return nil, err
	}
	return buildMessage(mt, cfg.RouterID, cfg.AreaID, cfg.AuthType, body, cfg.ChecksumMode)
}

func kindToType(kind string) (byte, error) {
	switch kind {
	case "hello":
		return TypeHello, nil
	case "db_description":
		return TypeDBDescription, nil
	case "link_state_request":
		return TypeLinkStateRequest, nil
	case "link_state_update":
		return TypeLinkStateUpdate, nil
	case "link_state_acknowledgment":
		return TypeLinkStateAcknowledgment, nil
	}
	return 0, fmt.Errorf("invalid event kind %q", kind)
}

func multiDstFor(ev *core.OSPFEvent) string {
	if ev.Kind == "hello" && len(ev.Neighbors) > 0 {
		return "224.0.0.5"
	}
	return "224.0.0.5"
}

func dirName(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func init() {
	layers.RegisterLayerGenerator("ospf", func() (layers.LayerGenerator, error) { return &OSPFGenerator{}, nil })
	layers.RegisterLayerValidator("ospf", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
