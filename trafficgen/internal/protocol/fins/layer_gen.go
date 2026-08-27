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
	sid := cfg.SID
	if sid == 0 {
		sid = 1
	}
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
			if err := emitMessage(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: response}); err != nil {
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
			if err := emitMessage(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: request}); err != nil {
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
				if err := emitMessage(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: response}); err != nil {
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
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		if cfg := GetConfig(*spec); cfg != nil && cfg.Sessions > 1 {
			return fmt.Errorf("fins: sessions (%d) multi-stream expansion is not supported on a layer chain (one flow per chain)", cfg.Sessions)
		}
		return nil
	})
}
