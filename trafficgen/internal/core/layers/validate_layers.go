package layers

import (
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// BuildLayersPlanner is the engine's injected layer-planner factory (P2c 层链
// 驱动生成): parses a raw "layers" config JSON into a per-task ChainPlanner.
// It re-runs the same parsing + completion + validation as ValidateLayers
// (strategy-creation-time validation is belt; this is braces — the stored
// config is trusted data, but a config edited out-of-band, or a layers JSON
// assembled by a non-validating caller, must still fail loudly at submit
// rather than silently generate a chain the registry would reject). The
// returned planner's Name is the effective protocol (given or inferred), so
// the worker's per-task lookup keys on it consistently with the legacy
// protocol-name planners. The protocol arg is the strategy's protocol field;
// when empty it is inferred from the chain (matching ValidateLayers).
func BuildLayersPlanner(protocol string, layersJSON json.RawMessage) (core.ProtocolPlanner, error) {
	effective, err := ValidateLayers(layersJSON, protocol)
	if err != nil {
		return nil, err
	}
	if effective == "" {
		return nil, fmt.Errorf("layers: no layers config")
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(layersJSON, &raw); err != nil {
		return nil, fmt.Errorf("layers: invalid layers JSON: %w", err)
	}
	chain := make([]Layer, 0, len(raw))
	for i, item := range raw {
		if len(item) != 1 {
			return nil, fmt.Errorf("layers[%d]: each layer entry must contain exactly one layer name", i)
		}
		for name, cfgRaw := range item {
			var cfg map[string]interface{}
			if len(cfgRaw) > 0 {
				if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
					return nil, fmt.Errorf("layers[%d] (%s): invalid config: %w", i, name, err)
				}
			}
			chain = append(chain, Layer{Name: name, Config: cfg})
		}
	}
	// Precheck generator instantiation so a chain containing a layer with no
	// implemented generator fails here (submit time), not at Plan time — the
	// same guard the planner's completedChain runs, surfaced earlier.
	for _, l := range chain {
		if _, err := newGenerator(l.Name); err != nil {
			return nil, err
		}
	}
	// CRITICAL-1 修复：传给 ChainPlanner 的必须是**补全后**的链——Plan 的
	// drive 从链上找 ip 层装配 L3，未补全的 [tcp] 会报 "no ip layer"，错误被
	// 驱动 goroutine 吞掉 → 任务报 completed 且 0 包（静默空流）。补全逻辑
	// 与 ValidateLayers 逐字一致：优先 CompleteChain（保留用户层 config）；
	// 单层链 legacy 豁免（V4 例外，传输层可作末层）时 CompleteChain 的
	// validateChain 拒绝末层，回退手动补全（depends_on 只向外插）——但必须
	// 保留 config 的变体：completeSynthesized 从裸协议名重建，config 全丢，
	// 会静默生成 schema 默认的包。补全必须在 factory 内完成（链要驱动生成），
	// 不能留到 Plan（completedChain 的 p.chain 分支无法识别豁免条件）。
	r := DefaultRegistry()
	// CWMP 载体检查：cwmp 终结层事件是完整 HTTP 帧（透传变换器），链上
	// 必须有 http 层（设计 §2：[tcp, http, cwmp]，tcp→cwmp 直连拒绝）。
	if hasLayer(chain, "cwmp") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("cwmp: terminal layer requires the http carrier layer ([tcp, http, cwmp]; tcp→cwmp direct chain rejected)")
	}
	// DOH 载体检查（66-doh 设计 §2/§7 wire fault layer_chain）：doh 终结层
	// 事件是完整 HTTP 帧（POST/GET + 响应），链上必须有 http 层（[tcp, http,
	// doh]，tcp→doh 直连拒绝）。
	if hasLayer(chain, "doh") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("doh: terminal layer requires the http carrier layer ([tcp, http, doh]; tcp→doh direct chain rejected, carrier missing)")
	}
	// ONVIF 载体检查（67-onvif v2.1.1 设计 §2）：onvif 终结层事件是完整
	// HTTP 帧（SOAP 1.2 透传变换器），链上必须有 http 层（[tcp, http, onvif]，
	// tcp→onvif 直连拒绝）。
	if hasLayer(chain, "onvif") && !hasLayer(chain, "http") {
		return nil, fmt.Errorf("onvif: terminal layer requires the http carrier layer ([tcp, http, onvif]; tcp→onvif direct chain rejected, carrier missing)")
	}
	completed, err := r.CompleteChain(chain)
	if err != nil {
		exempt := len(chain) == 1 && outerCategory(r, chain[0]) != CategoryTunnel
		if !(exempt && isTerminalEndError(err)) {
			return nil, err
		}
		completed = completeChainPreservingConfig(r, chain)
	}
	return NewChainPlannerFromChain(effective, completed), nil
}

// checkLayerDynObjects validates dynamic_value objects in one user-chain
// layer config (D-FTP-3 §1). Object on a non-allowlisted field →
// "does not support dynamic"; malformed object → indexed field-path error.
// Returns the config minus dynamic objects (scalars only) for the V9 path.
func checkLayerDynObjects(i int, lname string, cfg map[string]interface{}) (map[string]interface{}, error) {
	stripped := make(map[string]interface{}, len(cfg))
	for k, v := range cfg {
		m, isObj := v.(map[string]interface{})
		if !isObj {
			stripped[k] = v
			continue
		}
		// 非动态结构化值（wire_fault/mailbox/data_channel…，无 strategy
		// 键）不是动态对象：原样保留走 legacy V9 路径（无界字段跳过）。
		if _, looksDyn := m["strategy"]; !looksDyn {
			stripped[k] = v
			continue
		}
		where := fmt.Sprintf("layers[%d](%s).%s", i, lname, k)
		if !core.LayerDynAllowlisted(lname, k) {
			return nil, fmt.Errorf("%s does not support dynamic", where)
		}
		if msg := core.CheckLayerDynShape(lname, k, m); msg != "" {
			reason := msg
			if j := indexColonSpace(msg); j >= 0 {
				reason = msg[j+2:]
			}
			return nil, fmt.Errorf("%s: %s", where, reason)
		}
	}
	return stripped, nil
}

func indexColonSpace(s string) int {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == ':' && s[i+1] == ' ' {
			return i
		}
	}
	return -1
}

// ValidateLayers validates a user-supplied layer chain at strategy-creation
// time (P3, design §10.2 创建时校验清单): parse the "layers" array, complete
// hard dependencies (V8), then apply V1-V10. protocol is the strategy's
// protocol field; when empty it is inferred from the chain (§6.2). Returns
// the effective protocol (given or inferred) — the caller persists the
// inferred value back when protocol was empty.
//
// Entry point lives in this package — not core — because core cannot import
// layers (layers already imports core for FlowSpec/PacketConfig), and the
// registry/validation machinery is here. Callers (api/rest) import layers
// directly.
//
// V10/推断的"最外层"语义（§6.1 完整示例 [ip, gre, ip, tcp, http] +
// protocol "gre"）：最外层 = 补全后链上第一个非脚手架层——L3/L2/传输层
// （ip/eth/vlan/mpls/pppoe/tcp/udp）与隧道层 tls 是承载骨架，不算用户
// 意图；gre/http/dns 等用户协议层才算。全链都是骨架（独立 [ip→tcp] 传输
// flow）时回退末层。
//
// 单层链（[tcp]、[http]…）是 legacy 每协议风格——类名即末层，传输层当
// 末层合法（V4 豁免，ChainPlanner 合成链同口径）。隧道层单层（[tls]、
// [gre]）不豁免：隧道必须包内层（V6）。豁免路径改用手动补全
// （depends_on 只向外插，末层保持用户层），跳过 V4 继续走其余规则。
//
// Field-range checking (V9) applies to explicitly-present config keys only:
// a user-written "dst_port": 0 is an explicit request for 0 (§6.4), while an
// absent key is filled from the schema default at generation time (R2), so
// absent keys are never range-checked here. Explicit 0 on a field whose
// minimum is > 0 (mss ≥ 536) means "use the schema default" — same
// convention as the flat-config validator — and is not range-checked either.
//
// P3 scope (设计 §14.1): this stage validates and infers protocol only —
// the generated chain does NOT drive packet construction yet. Generation
// (P2c 层链驱动生成) consumes top-level flat keys via mapToFlowSpec and
// derives the chain from the protocol name; the layers config is validated
// here and persisted, but its field values are not applied until the
// generation stage wires the chain in. A layers config that passes
// validation but whose fields the flat path ignores (e.g. 单层 [mpls],
// 生成走 legacy flat 路径) is therefore validated-but-not-yet-effective;
// the mislead risk is tracked in P2c 集成测试 (T11-T13).
func ValidateLayers(layersJSON json.RawMessage, protocol string) (string, error) {
	if len(layersJSON) == 0 {
		return "", nil // no layers field = legacy flat config path
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(layersJSON, &raw); err != nil {
		return "", fmt.Errorf("layers: invalid layers JSON: %w", err)
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("layers: empty layer chain")
	}
	chain := make([]Layer, 0, len(raw))
	for i, item := range raw {
		// 每项 = { 层名: 配置 }（设计 §3.1：层名即键，值是该层字段配置）。
		// 一个条目必须恰好一个层（多键 = 一条里塞了两层，拒绝）。
		if len(item) != 1 {
			return "", fmt.Errorf("layers[%d]: each layer entry must contain exactly one layer name", i)
		}
		for name, cfgRaw := range item {
			var cfg map[string]interface{}
			if len(cfgRaw) > 0 {
				if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
					return "", fmt.Errorf("layers[%d] (%s): invalid config: %w", i, name, err)
				}
			}
			chain = append(chain, Layer{Name: name, Config: cfg})
		}
	}

	r := DefaultRegistry()
	for i := range chain {
		if !r.Has(chain[i].Name) {
			return "", errf("layers: unknown layer %q (position %d)", chain[i].Name, i)
		}
	}

	completed, err := r.CompleteChain(chain)
	// 单层链 legacy 豁免（V4 例外，ChainPlanner 合成链同口径）：[tcp] 的
	// 末层就是协议层本身，传输层当末层合法。隧道层（tls/gre）不豁免——
	// 隧道必须包内层（V6）。豁免路径改用手动补全（depends_on 只向外插，
	// 末层保持用户层），跳过 V4 继续走其余规则。
	exempt := len(chain) == 1 && outerCategory(r, chain[0]) != CategoryTunnel
	if err != nil {
		if !(exempt && isTerminalEndError(err)) {
			return "", err
		}
		completed = completeSynthesized(r, chain[0].Name)
	}
	if err := r.ValidateChain(completed); err != nil {
		// 同上豁免：手动补全后的链末层仍是用户层（tcp），V4 仍会拒绝，
		// 豁免条件下吞掉该错误，其余规则原样生效。
		if !(exempt && isTerminalEndError(err)) {
			return "", err
		}
	}
	// 字段范围（V9）：用户链各层（config 只保留在用户层上——
	// completeSynthesized 丢弃 config，单层豁免路径必须回到用户层校验）
	// + 补全后全链（插入的依赖层，config 为空天然通过）。
	for i := range chain {
		// D-FTP-3 §1: 动态对象先行——同键二态：对象值走 dynamic_value
		// 形状检查（带用户链下标的精确路径），标量走既有 V9。
		stripped, err := checkLayerDynObjects(i, chain[i].Name, chain[i].Config)
		if err != nil {
			return "", err
		}
		if err := r.ValidateLayerConfig(Layer{Name: chain[i].Name, Config: stripped}); err != nil {
			return "", err
		}
	}
	for i := range completed {
		// D-FTP-3: 补全链沿用用户层 config 引用（含已校验的动态对象）——
		// 用户循环已逐个校验，这里只剥离对象值走标量 V9（插入的依赖层
		// config 为空，天然无对象）。
		strippedDone := make(map[string]interface{}, len(completed[i].Config))
		for k, v := range completed[i].Config {
			if _, isObj := v.(map[string]interface{}); isObj {
				continue
			}
			strippedDone[k] = v
		}
		if err := r.ValidateLayerConfig(Layer{Name: completed[i].Name, Config: strippedDone}); err != nil {
			return "", err
		}
	}

	// V10 + 推断：protocol 必须等于最外层协议层（非脚手架层）。
	outermost := outermostProtocol(completed)
	if protocol != "" {
		if outermost != protocol {
			// 隧道层特例：protocol 显式指定为隧道层（如 "tls"）时，最外层是
			// 内层协议（如 "http"），因为隧道层在 outermostProtocol 中被跳过
			// （tls 承载骨架、非用户协议意图）。仅当 protocol 是隧道层且确实
			// 在链上时允许该不匹配。
			if schema, ok := r.Get(protocol); ok && schema.Category == CategoryTunnel {
				found := false
				for _, l := range completed {
					if l.Name == protocol {
						found = true
						break
					}
				}
				if found {
					return protocol, nil
				}
			}
			// 变换器特例：protocol 是 TransformEvents 标记层（如 http 之于
			// http_flv 链 [ip→tcp→http→http_flv]），在链上非末层位置充当事件
			// 变换器（不产自己的协议报文）。与 tls 承载骨架同类豁免。
			// 豁免必须校验位置：仅当 protocol 层出现在**非末层**位置才成立
			// ——若它当末层（如 [ip,gre,ip,tcp,http] + protocol "http"），
			// 它是真正的终结层而非变换器，V10 应照常拒绝不匹配。
			if schema, ok := r.Get(protocol); ok && schema.TransformEvents {
				for i, l := range completed {
					if l.Name == protocol && i < len(completed)-1 {
						return protocol, nil
					}
				}
			}
			return "", errf("layers: protocol %q does not match outermost layer %q", protocol, outermost)
		}
		return protocol, nil // 显式 protocol 原样返回（调用方仅 protocol=="" 时回填）
	}
	return outermost, nil
}

// outermostProtocol resolves the strategy's protocol from a completed chain:
// the outermost layer that is not L3/L2/transport scaffolding (承载骨架,
// §6.1 完整示例 [ip, gre, ip, tcp, http] + protocol "gre")。tls 是隧道层
// （隧道必须包内层 V6），作为 TLS 承载的协议（如 tls→stun）并非用户协议
// 意图，同样计入骨架被跳过；gre 例外——它是自成一体的用户协议层，不跳过。
// 全链都是骨架（独立 [ip→tcp] 传输 flow）时回退末层。
func outermostProtocol(completed []Layer) string {
	for i := range completed {
		switch completed[i].Name {
		case "ip", "eth", "vlan", "mpls", "pppoe", "tcp", "udp", "tls", "http":
			continue
		}
		return completed[i].Name
	}
	return completed[len(completed)-1].Name
}

// outerCategory returns the registry category of a user chain's first layer
// (单层链豁免判定用；层已确认存在)。
func outerCategory(r *Registry, l Layer) LayerCategory {
	s, _ := r.Get(l.Name)
	return s.Category
}
