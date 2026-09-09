package schema

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// FlowControl is the minimal flow-control view the schema entry needs.
// Handlers convert their own request type into this before calling.
type FlowControl struct {
	Type  string
	Value float64
}

// ValidateStrategy is the single entry for strategy create/update validation.
// Shape (strategy.json) and semantic checks run on every call; semantic
// errors use handler-identical text and win when both fire, so REST/MCP
// callers see stable messages. It returns the effective protocol (layers
// mode may infer it when empty) plus field errors. Callers surface errors
// as 400 with the joined message; no handler may add its own shape checks.
func ValidateStrategy(mode, protocol string, config map[string]any, fc *FlowControl) (string, ValidationErrors) {
	doc := map[string]any{
		"name":     "x",
		"mode":     mode,
		"protocol": protocol,
		"config":   config,
	}
	if fc != nil {
		doc["flow_control"] = map[string]any{"type": fc.Type, "value": fc.Value}
	}
	// Both layers run on every call: semantic errors carry the historic
	// handler text and win when both fire; shape errors cover the rest.
	shapeErrs := ValidateStrategyShape(doc)
	effProto, semErrs := validateStrategySemantic(mode, protocol, config, fc)
	if len(semErrs) > 0 {
		return effProto, semErrs
	}
	return effProto, shapeErrs
}

// validateStrategySemantic runs the checks JSON Schema cannot express,
// mirroring the handler order in strategy_handler.go (createSynthStrategy /
// createReplayStrategy / Update): network formats, config ranges, layers
// inference, protocol allowlist, sub-config ranges, TFTP batch rule.
func validateStrategySemantic(mode, protocol string, config map[string]any, fc *FlowControl) (string, ValidationErrors) {
	var errs ValidationErrors
	fail := func(format string, args ...any) {
		errs = append(errs, &FieldError{Message: fmt.Sprintf(format, args...)})
	}

	if mode == "replay" {
		// Handler-identical messages first: layers rejection and time-only
		// flow control use the exact historic text (tests assert substrings).
		if _, ok := config["layers"]; ok {
			fail("layers is not valid for replay strategies (replay config only takes pcap_asset_id/speed/direction/checksum_mode)")
		}
		if fc != nil && fc.Type != "time" {
			fail("replay strategy flow_control only supports type=time")
		}
		if len(errs) > 0 {
			return protocol, errs
		}
		raw, err := json.Marshal(config)
		if err != nil {
			fail("invalid config format")
			return protocol, errs
		}
		if err := core.ValidateReplaySpec(raw); err != nil {
			fail("%s", err.Error())
		}
		return protocol, errs
	}

	// Synth path. Flow-control type/value use the exact historic text
	// (strategy tests assert the "invalid flow_control type" substring).
	if fc != nil {
		switch fc.Type {
		case "flows", "bps", "time":
		default:
			fail("invalid flow_control type: must be flows, bps, or time")
		}
		if fc.Value <= 0 {
			fail("flow_control value must be positive")
		}
		if len(errs) > 0 {
			return protocol, errs
		}
	}
	if msg := validateConfigNetworkLocal(config); msg != "" {
		fail("%s", msg)
	}
	if err := core.ValidateConfigRanges(config); err != nil {
		fail("%s", err.Error())
	}
	if rawLayers, ok := config["layers"]; ok {
		layersJSON, err := json.Marshal(rawLayers)
		if err != nil {
			fail("invalid layers format: %s", err.Error())
		} else if inferred, err := layers.ValidateLayers(layersJSON, protocol); err != nil {
			fail("%s", err.Error())
		} else {
			protocol = inferred
		}
	}
	if protocol == "" || !core.IsAllowedProtocol(protocol) {
		fail("invalid or missing protocol: %s", protocol)
	}
	if err := core.ValidateProtocolSubConfigs(config, protocol); err != nil {
		fail("%s", err.Error())
	}
	if fc != nil && fc.Type == "flows" && protocol == "tftp" {
		if msg := checkTFTPServerTID(config, fc.Value); msg != "" {
			fail("%s", msg)
		}
	}
	return protocol, errs
}

// checkTFTPServerTID mirrors the handler batch rule: a pinned server_tid
// collides when one strategy fans out to more than one flow.
func checkTFTPServerTID(config map[string]any, flows float64) string {
	if int(flows) <= 1 {
		return ""
	}
	sub, ok := config["tftp"].(map[string]any)
	if !ok {
		return ""
	}
	tv, ok := sub["server_tid"]
	if !ok {
		return ""
	}
	f, ok := tv.(float64)
	if !ok || int64(f) <= 0 {
		return ""
	}
	return fmt.Sprintf("tftp: server_tid %d conflicts with another flow in the same batch", int64(f))
}

var macRe = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)

// validateConfigNetworkLocal mirrors validateConfigNetwork in
// strategy_handler.go (unexported there): string-typed IP/MAC fields are
// format-checked; absent/empty/non-string values are skipped.
func validateConfigNetworkLocal(config map[string]any) string {
	for _, key := range []string{"src_ip", "dst_ip"} {
		if val, ok := config[key]; ok {
			if s, ok := val.(string); ok && s != "" && net.ParseIP(s) == nil {
				return "invalid IP format: " + key + " = " + s
			}
		}
	}
	for _, key := range []string{"src_mac", "dst_mac"} {
		if val, ok := config[key]; ok {
			if s, ok := val.(string); ok && s != "" && !macRe.MatchString(s) {
				return "invalid MAC format: " + key + " = " + s
			}
		}
	}
	return ""
}

// ValidateTaskCreate is the single entry for task create validation (both
// strategy_ids and inline-batch forms). Shape first via task.json, then the
// semantic checks JSON Schema cannot express: flow-control envelope text,
// replay+bps conflict against the loaded strategies, batch class semantics
// via core.ValidateBatchSpec. DB lookups (strategy existence/ownership,
// port-group existence) stay in the handler — they need the request context.
func ValidateTaskCreate(doc map[string]any, strategies []StrategyView) ValidationErrors {
	if shapeErrs := ValidateTaskShape(doc); len(shapeErrs) > 0 {
		// Flow-control message parity: historic text wins over schema enum
		// text when the caller set an explicit flow_control.
		if fc, ok := doc["flow_control"].(map[string]any); ok {
			if t, _ := fc["type"].(string); t != "" {
				switch t {
				case "flows", "bps", "time":
				default:
					return ValidationErrors{{Message: "invalid flow_control type: must be flows, bps, or time"}}
				}
			}
			if v, ok := fc["value"].(float64); ok && v <= 0 {
				return ValidationErrors{{Message: "flow_control value must be positive"}}
			}
		}
		return shapeErrs
	}
	var errs ValidationErrors
	if fc, ok := doc["flow_control"].(map[string]any); ok {
		if t, _ := fc["type"].(string); t != "" {
			switch t {
			case "flows", "bps", "time":
			default:
				errs = append(errs, &FieldError{Message: "invalid flow_control type: must be flows, bps, or time"})
			}
		}
		if v, ok := fc["value"].(float64); ok && v <= 0 {
			errs = append(errs, &FieldError{Message: "flow_control value must be positive"})
		}
		if t, _ := fc["type"].(string); t == "bps" {
			for _, s := range strategies {
				if s.Mode == "replay" && (s.SpeedMode == "original" || s.SpeedMode == "multiplier") {
					errs = append(errs, &FieldError{Message: "replay strategy " + quoted(s.Name) + " has " + s.SpeedMode + " speed limit, cannot combine with bps task-level flow control"})
				}
			}
		}
	}
	if batch, ok := doc["batch"].(map[string]any); ok {
		if shapeErrs := ValidateBatchShape(batch); len(shapeErrs) > 0 {
			errs = append(errs, shapeErrs...)
		} else if err := validateBatchSemantic(batch); err != nil {
			errs = append(errs, &FieldError{Message: err.Error()})
		}
	}
	return errs
}

// validateBatchSemantic decodes the shape-checked batch doc into
// core.BatchSpec and runs core.ValidateBatchSpec (class ids, protocol
// allowlist, per-class ranges, replay specs). Shape already passed, so
// decode errors here are internal, not user errors.
func validateBatchSemantic(batch map[string]any) error {
	raw, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("invalid batch format")
	}
	var spec core.BatchSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return fmt.Errorf("invalid batch format: %s", err.Error())
	}
	return core.ValidateBatchSpec(spec)
}

// StrategyView is the minimal strategy view ValidateTaskCreate needs for the
// replay+bps conflict check. Handlers build it from storage models.
type StrategyView struct {
	Name      string
	Mode      string
	SpeedMode string
}

func quoted(s string) string {
	return "\"" + s + "\""
}
