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
	// D-SIP-2 WP-A：sip 层 sessions[] 互斥判死（与 dialog 同给即拒；空数组
	// 同锚词面）——create-time 400；Planner.Validate 侧同名锚词做 task-time
	// 背 door（C 类：两路独立闭合，radius 扁平缺省同口径）。
	if msg := checkSIPSessionsMutex(config); msg != "" {
		fail("%s", msg)
	}
	// D-SIP-2 WP-B：medias[] 与 media 互斥（空数组同锚词面）——同 sessions
	// 口径，Planner.Validate 背 door。
	if msg := checkSIPMediasMutex(config); msg != "" {
		fail("%s", msg)
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
// D-REWORK-1（CORE_MEMORY 1.11 顶层白名单）：src_mac/dst_mac 同列——MAC 真相
// 住 eth 层，顶层影子与 layers 并存同判混用。
func checkLayerFlatConflict(config map[string]any) string {
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "src_mac", "dst_mac"} {
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
		// D-H323-1：h323 层端口住层（1.2 已批偏离），12.9 执法同权——
		// 静态标量端口 + flows>1 与 tcp/udp 同拒（依赖链③执法洞修补）。
		// D-MPLS-1：mpls 同款延续。D-NGAP-1：ngap 同款延续。
		// D-TELNET-1：telnet 同款延续。D-SIP-1：sip 同款延续。
		// D-RADIUS-1：radius 同款延续。
		for _, lname := range []string{"ip", "tcp", "udp", "eth", "h323", "mpls", "ngap", "telnet", "sip", "radius"} {
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
			for k, v := range subMap {
				if m, isObj := v.(map[string]any); isObj && m != nil {
					if _, looksDyn := m["strategy"]; looksDyn {
						hasDyn = true
					}
					continue
				}
				// D-SIP-2 WP-A：sessions[] 内嵌端口同权——标量入 hasScalar、
				// 动态对象入 hasDyn（12.9 执法洞修补，嵌套结构不豁免）。
				if k != "sessions" && k != "medias" {
					continue
				}
				sessArr, ok := v.([]any)
				if !ok {
					continue
				}
				for _, sItem := range sessArr {
					sess, _ := sItem.(map[string]any)
					if sess == nil {
						continue
					}
					for _, pf := range []string{"src_port", "dst_port", "call_id"} {
						pv, ok := sess[pf]
						if !ok || pv == nil {
							continue
						}
						if pm, isObj := pv.(map[string]any); isObj {
							// 动态对象（含 call_id 的 pattern/fixed）=逐流
							// 有别证明入 hasDyn；标量只对端口入 hasScalar
							// （call_id/dialog 静态文本不构成四元组复制面，
							// 两流同 Call-ID 是显式声明语义）。
							if _, looksDyn := pm["strategy"]; looksDyn {
								hasDyn = true
							}
						} else if pf != "call_id" {
							hasScalar = true
						}
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
// D-GOOSE-1 ⑥：含 eth（src_mac/dst_mac）——eth-only 链 flows>1 无四元组
// 可查时静默发 N 条重复流（sqNum 撞号），通用修（sv/isis 同享）。
// checkSIPSessionsMutex (D-SIP-2 WP-A): sip 层 sessions[] 与 dialog 互斥
// （sessions 是多会话形态，dialog 是单会话速记——同给语义不明即拒）；空
// sessions 数组同锚词面（空结构无独立语义，不给静默退化）。锚词带 sip:
// 前缀=协议锁文案（radius 系文案先例）。
func checkSIPSessionsMutex(config map[string]any) string {
	arr, ok := config["layers"].([]any)
	if !ok {
		return ""
	}
	for _, item := range arr {
		layer, _ := item.(map[string]any)
		sip, _ := layer["sip"].(map[string]any)
		if sip == nil {
			continue
		}
		_, hasDialog := sip["dialog"]
		_, hasSessions := sip["sessions"]
		if hasSessions && hasDialog {
			return "sip: sessions and dialog are mutually exclusive (use sessions for the multi-session shape, dialog for the single-dialog shorthand)"
		}
		if sess, ok := sip["sessions"].([]any); ok && len(sess) == 0 {
			return "sip: sessions and dialog are mutually exclusive (use sessions for the multi-session shape, dialog for the single-dialog shorthand)"
		}
	}
	return ""
}

// checkSIPMediasMutex (D-SIP-2 WP-B): sip 层 medias[] 与 media 互斥
// （多流形态 vs 单流速记——语义与 sessions×dialog 同构）；空 medias 数组
// 同锚词面。
func checkSIPMediasMutex(config map[string]any) string {
	arr, ok := config["layers"].([]any)
	if !ok {
		return ""
	}
	for _, item := range arr {
		layer, _ := item.(map[string]any)
		sip, _ := layer["sip"].(map[string]any)
		if sip == nil {
			continue
		}
		_, hasMedia := sip["media"]
		_, hasMedias := sip["medias"]
		if hasMedias && hasMedia {
			return "sip: media and medias are mutually exclusive (use media for a single stream, medias for the multi-stream shape)"
		}
		if medias, ok := sip["medias"].([]any); ok && len(medias) == 0 {
			return "sip: media and medias are mutually exclusive (use media for a single stream, medias for the multi-stream shape)"
		}
	}
	return ""
}

func layerTupleFields(lname string) []string {
	if lname == "ip" {
		return []string{"src", "dst"}
	}
	if lname == "eth" {
		return []string{"src_mac", "dst_mac"}
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
