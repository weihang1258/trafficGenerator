package fins

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type FINSGenerator struct{}

func (g *FINSGenerator) Name() string { return "fins" }

func (g *FINSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("fins generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg, err := configFromMeta(req.Meta.FINS)
	if err != nil {
		return err
	}
	if err := (&Planner{}).Validate(core.FlowSpec{Metadata: map[string]interface{}{MetadataKey: cfg}}); err != nil {
		return err
	}
	cfg = cloneConfig(cfg)
	transport := cfg.Transport
	if transport == "" {
		transport = "udp"
	}
	if len(cfg.Commands) == 0 {
		cfg.Commands = []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}}
	}
	// count 型多会话（P0a 模式）：sessions=N 每会话一条独立流，UDP 源端口 =
	// 顶层 src_port + i（事件带 SrcPort，udp 层逐事件覆盖；TCP 会话则由 tcp
	// 层挥旧握新）。每会话 SID 序列独立从基准起。
	sessions := cfg.Sessions
	if sessions < 1 {
		sessions = 1
	}
	sid := cfg.SID
	if sid == 0 {
		sid = 1
	}
	for i := 0; i < sessions; i++ {
		var srcPort uint16
		if sessions > 1 {
			base := req.Meta.SrcPort
			if base == 0 {
				base = 1245
			}
			srcPort = base + uint16(i)
		}
		if err := emitSessionCommands(ctx, cfg, req, transport, sid, srcPort); err != nil {
			return err
		}
	}
	return nil
}

// emitSessionCommands emits the command/response sequence for one session.
// sidSeed is the session's starting SID; srcPort the session's source port
// override (0 = default flow port).
func emitSessionCommands(ctx context.Context, cfg *FINSConfig, req *layers.GenRequest, transport string, sidSeed byte, srcPort uint16) error {
	sid := sidSeed
	for _, command := range cfg.Commands {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if command.Command == 0 {
			command.Command = CommandMemoryAreaRead
		}
		requestSID := sid
		if command.SID != 0 {
			requestSID = command.SID
		}
		if command.Direction == "down" {
			response, err := BuildFrameWithConfig(cfg, command, true, requestSID)
			if err != nil {
				return err
			}
			if transport == "tcp" {
				response = wrapTCP(response)
			}
			if err := emitMessage(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: response, SrcPort: srcPort}); err != nil {
				return err
			}
		} else {
			request, err := BuildFrameWithConfig(cfg, command, false, requestSID)
			if err != nil {
				return err
			}
			if transport == "tcp" {
				request = wrapTCP(request)
			}
			if err := emitMessage(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: request, SrcPort: srcPort}); err != nil {
				return err
			}
			if command.ExpectResponse == nil || *command.ExpectResponse {
				response, err := BuildFrameWithConfig(cfg, command, true, requestSID)
				if err != nil {
					return err
				}
				if transport == "tcp" {
					response = wrapTCP(response)
				}
				if err := emitMessage(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: response, SrcPort: srcPort}); err != nil {
					return err
				}
			}
		}
		if command.Direction != "down" && cfg.SIDAuto {
			sid++
			if sid == 0 {
				sid = 1
			}
		}
	}
	return nil
}

func emitMessage(ctx context.Context, emit func(layers.MessageEvent) error, event layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(event)
}

func (g *FINSGenerator) GenEvents() layers.EventGenerator { return g }
func (g *FINSGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("fins generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func configFromMeta(value interface{}) (*FINSConfig, error) {
	switch cfg := value.(type) {
	case nil:
		// P0b-2：空配置默认化并产默认流（udp + dm read）。
		return &FINSConfig{Transport: "udp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}}, SIDAuto: true, SIDAutoSet: true}, nil
	case *FINSConfig:
		if cfg == nil {
			return &FINSConfig{Transport: "udp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}}, SIDAuto: true, SIDAutoSet: true}, nil
		}
		return cfg, nil
	case map[string]interface{}:
		raw, err := json.Marshal(cfg)
		if err != nil {
			return nil, fmt.Errorf("fins generator: invalid fins config: %w", err)
		}
		var parsed FINSConfig
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("fins generator: invalid fins config: %w", err)
		}
		return &parsed, nil
	case json.RawMessage:
		var parsed FINSConfig
		if err := json.Unmarshal(cfg, &parsed); err != nil {
			return nil, fmt.Errorf("fins generator: invalid fins config: %w", err)
		}
		return &parsed, nil
	default:
		return nil, fmt.Errorf("fins generator: unsupported fins config type %T", value)
	}
}

func init() {
	layers.RegisterLayerGenerator("fins", func() (layers.LayerGenerator, error) { return &FINSGenerator{}, nil })
	layers.RegisterLayerValidator("fins", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
