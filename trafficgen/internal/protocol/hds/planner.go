package hds

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// HDSGenerator is the hds terminal-layer generator ([ip→tcp→http→hds] chain).
// It produces HDS body events (F4M manifest text, bootstrap bytes, F4F fragment bytes);
// the http layer above it wraps each event in an HTTP GET/response pair.
type HDSGenerator struct{}

// Name returns "hds".
func (g *HDSGenerator) Name() string { return "hds" }

// Generate produces one MessageEvent per HDS session (down direction).
// Each event carries the body bytes (F4M manifest, bootstrap bytes, or F4F fragment bytes).
func (g *HDSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("hds generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	hcfg := req.Meta.HDS
	if hcfg == nil {
		hcfg = &core.HDSConfig{Profile: "hds_http1"}
	}

	for _, s := range hcfg.Sessions {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		body, err := buildSessionBody(&s, hcfg)
		if err != nil {
			return fmt.Errorf("hds: build body for %s (%s): %w", s.URI, s.Kind, err)
		}
		if err := req.EmitMsg(layers.MessageEvent{Up: false, Bytes: body}); err != nil {
			return err
		}
	}
	return nil
}

// buildSessionBody builds the body bytes for one HDS session.
func buildSessionBody(s *core.HDSSession, hcfg *core.HDSConfig) ([]byte, error) {
	switch s.Kind {
	case "manifest":
		if hcfg.Manifest == nil {
			return nil, fmt.Errorf("hds: manifest config is nil for manifest session")
		}
		playlist, err := buildF4MManifest(hcfg.Manifest, hcfg.Profile)
		if err != nil {
			return nil, err
		}
		return []byte(playlist), nil

	case "bootstrap":
		if hcfg.Manifest == nil || len(hcfg.Manifest.Media) == 0 {
			return nil, fmt.Errorf("hds: manifest/media required for bootstrap session")
		}
		// Check for explicit base64 bootstrap bytes
		for _, bi := range hcfg.Manifest.BootstrapInfos {
			if bi.Base64 != "" {
				decoded, err := base64.StdEncoding.DecodeString(bi.Base64)
				if err != nil {
					return nil, fmt.Errorf("hds: bootstrap base64 decode: %w", err)
				}
				return decoded, nil
			}
		}
		// Build bootstrap box from media config
		media := &hcfg.Manifest.Media[0]
		box, err := buildBootstrapBox(media, hcfg.Profile)
		if err != nil {
			return nil, err
		}
		return box, nil

	case "fragment":
		if hcfg.Manifest == nil || len(hcfg.Manifest.Media) == 0 {
			return nil, fmt.Errorf("hds: manifest/media required for fragment session")
		}
		media := &hcfg.Manifest.Media[0]
		if len(media.Fragments) == 0 {
			return nil, fmt.Errorf("hds: no fragments configured for media")
		}
		frag := media.Fragments[0]
		body := resolveBody(frag.Body, frag.BodyB64)
		if len(body) == 0 {
			body = []byte("dummy fragment content")
		}
		return buildF4FFragment(body), nil

	default:
		return nil, fmt.Errorf("hds: unknown session kind %q", s.Kind)
	}
}

// GenEvents marks this generator as a message event producer.
func (g *HDSGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent satisfies the EventGenerator interface; events flow through GenRequest.EmitMsg.
func (g *HDSGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("hds generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// validateHDSConfig validates the HDS terminal-layer config. It is invoked by
// the chain planner's protocolValidator at strategy creation, so negative
// configs are rejected with a 400 before any task is created. It checks the
// same invariants buildSessionBody relies on (core.FlowSpec.HDS carries the
// terminal-layer HDS config in a [ip→tcp→http→hds] chain via
// translateTerminalConfig; nil means the chain's terminal layer is not hds).
func validateHDSConfig(spec *core.FlowSpec) error {
	if spec.HDS == nil {
		return nil
	}
	h := spec.HDS
	if len(h.Sessions) == 0 {
		return fmt.Errorf("hds: sessions is required")
	}
	for i := range h.Sessions {
		s := &h.Sessions[i]
		switch s.Kind {
		case "manifest":
			if err := validateManifest(h.Manifest); err != nil {
				return err
			}
		case "bootstrap":
			if h.Manifest == nil || len(h.Manifest.Media) == 0 {
				return fmt.Errorf("hds: manifest/media required for bootstrap session")
			}
		case "fragment":
			if h.Manifest == nil || len(h.Manifest.Media) == 0 {
				return fmt.Errorf("hds: manifest/media required for fragment session")
			}
			if len(h.Manifest.Media[0].Fragments) == 0 {
				return fmt.Errorf("hds: no fragments configured for media")
			}
		default:
			return fmt.Errorf("hds: unknown session kind %q", s.Kind)
		}
	}
	return nil
}

// validateManifest enforces the F4M manifest invariants shared by the build
// path (builder.go buildF4MManifest): id, stream_type and at least one media
// entry are required, and a non-empty bootstrap_infos entry must carry valid
// base64 (decoded at build time).
func validateManifest(m *core.HDSManifest) error {
	if m == nil {
		return fmt.Errorf("hds: manifest config is nil")
	}
	if m.ID == "" {
		return fmt.Errorf("hds: manifest id is required")
	}
	if m.StreamType == "" {
		return fmt.Errorf("hds: manifest stream_type is required")
	}
	if len(m.Media) == 0 {
		return fmt.Errorf("hds: manifest must have at least one media entry")
	}
	for i := range m.BootstrapInfos {
		bi := &m.BootstrapInfos[i]
		if bi.Base64 == "" {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(bi.Base64); err != nil {
			return fmt.Errorf("hds: bootstrap base64 decode: %w", err)
		}
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("hds", func() (layers.LayerGenerator, error) {
		return &HDSGenerator{}, nil
	})
	layers.RegisterLayerValidator("hds", validateHDSConfig)
}