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
		// Explicit null is a value, not absence: callers (MCP) must omit
		// unset optionals instead of sending null. The schema "type" errors
		// for null are reflect jargon, so translate them to a human message.
		if _, ok := config["layers"]; ok {
			fail("layers is not valid for replay strategies (replay config only takes pcap_asset_id/speed/direction/checksum_mode)")
		}
		for _, k := range []string{"speed", "direction", "checksum_mode", "rewrites", "flow_scaling", "loop"} {
			if v, ok := config[k]; ok && v == nil {
				fail("%s is null; omit it to use the engine default", k)
			}
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
	// Step 1（全协议扁平删除）：顶层四元组/count 任一出现即 400（先于 static
	// copy 检查：判死语境下 "Omit src_port" 是错误指引，正确指引是迁层链）。
	// 条件与文案的单一真相在 core.CheckProtoFlat（ftp 委托原 CheckFTPFlat，
	// 文案锁死；convert.go ValidateBatchSpec 的 batch 类 shape 门共用）。
	if msg := core.CheckProtoFlat(protocol, config); msg != "" {
		fail("%s", msg)
	}
	if fc != nil && fc.Type == "flows" && protocol == "tftp" {
		if msg := checkTFTPServerTID(config, fc.Value); msg != "" {
			fail("%s", msg)
		}
	}
	if fc != nil && fc.Type == "flows" && int(fc.Value) > 1 {
		if msg := checkStaticCopy(config); msg != "" {
			fail("%s", msg)
		}
		if msg := checkLayerChainStaticCopy(config, fc.Value); msg != "" {
			fail("%s", msg)
		}
	}
	// D-FTP-3: layers 与顶层扁平四元组混用拒绝（只拦新建/更新；存量策略
	// 已入库的不追溯，任务启动不复查）。位置在所有形状/网络检查之后，
	// 文案给迁移指引。
	if _, hasLayers := config["layers"]; hasLayers {
		if msg := checkLayerFlatConflict(config); msg != "" {
			fail("%s", msg)
		}
	}
	return protocol, errs
}

// checkLayerFlatConflict (D-FTP-3, CORE_MEMORY §1): layers 与顶层扁平四元组
// 任一共存即拒绝。地址写 ip 层 src/dst，端口写 tcp/udp 层 src_port/dst_port。
func checkLayerFlatConflict(config map[string]any) string {
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port"} {
		if v, ok := config[k]; ok && v != nil {
			return "config mixes layers with flat four-tuple field " + k + " (use ip.src/ip.dst for addresses, tcp/udp src_port/dst_port for ports)"
		}
	}
	return ""
}

// checkLayerChainStaticCopy (D-FTP-3): 层链形状下显式标量四元组 + 无对象 +
// flows>1 → 拒绝（逃生口=层内字段写动态对象）。仅当层内有任一四元组字段被
// 显式写成标量时触发；全缺省层（如 [{tcp:{}},{http:{}}]）不触发。
// D-DNS-1 修正：逃生口不限四元组层——业务层动态对象（dns.name/http.uri/
// tls.sni 等同 parseLayerDyn 口径）同样证明"流间有别"，豁免。只认三层
// （ip/tcp/udp）的旧逻辑会把纯业务动态多流误杀（dns_name_dynamic 实证）。
func checkLayerChainStaticCopy(config map[string]any, flows float64) string {
	if int(flows) <= 1 {
		return ""
	}
	arr, ok := config["layers"].([]any)
	if !ok {
		return ""
	}
	hasScalar, hasDyn := false, false
	for _, item := range arr {
		layer, _ := item.(map[string]any)
		for _, lname := range []string{"ip", "tcp", "udp"} {
			sub, _ := layer[lname].(map[string]any)
			if sub == nil {
				continue
			}
			for _, f := range layerTupleFields(lname) {
				v, ok := sub[f]
				if !ok || v == nil {
					continue
				}
				if _, isObj := v.(map[string]any); isObj {
					hasDyn = true
				} else {
					hasScalar = true
				}
			}
		}
		// 业务层动态对象逃生口（D-DNS-1）：allowlist 开字段的对象写法即
		// "逐流有别"证明——与四元组层对象同等豁免。只看对象形状（strategy
		// 键），不重复 allowlist 语义校验（ValidateLayers 管）。
		for lname, sub := range layer {
			if lname == "ip" || lname == "tcp" || lname == "udp" {
				continue
			}
			subMap, _ := sub.(map[string]any)
			if subMap == nil {
				continue
			}
			for _, v := range subMap {
				if m, isObj := v.(map[string]any); isObj && m != nil {
					if _, looksDyn := m["strategy"]; looksDyn {
						hasDyn = true
					}
				}
			}
		}
	}
	if hasScalar && !hasDyn {
		return "layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). Write the varying field as a dynamic object inside its layer (ip.src/ip.dst, tcp/udp src_port/dst_port)"
	}
	return ""
}

// layerTupleFields returns the four-tuple-ish field names of a layer.
func layerTupleFields(lname string) []string {
	if lname == "ip" {
		return []string{"src", "dst"}
	}
	return []string{"src_port", "dst_port"}
}

// checkStaticCopy (D-FTP-2, CORE_MEMORY §12): flows>1 with a pinned flat
// src_port would emit N identical 4-tuples — the static copy anti-pattern.
// Only applies to configs WITHOUT layers[] (layer-chain shapes are covered
// by checkLayerChainStaticCopy instead, D-FTP-3). Strategy-level tuples was
// withdrawn (D-FTP-3 H2): no tuples exemption here — the flat escape hatches
// are omit src_port (auto-increment) or migrate to a layer chain with the
// port as a dynamic object.
func checkStaticCopy(config map[string]any) string {
	if _, hasLayers := config["layers"]; hasLayers {
		return ""
	}
	if v, ok := config["src_port"]; ok && v != nil {
		if f, ok := v.(float64); ok {
			return fmt.Sprintf("src_port %d is pinned but flows > 1: every flow would emit an identical 4-tuple (static copy). Omit src_port (auto-increment per flow) or use a layer chain with the port as a dynamic object", int64(f))
		}
	}
	return ""
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
