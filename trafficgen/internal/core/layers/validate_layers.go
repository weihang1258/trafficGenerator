package layers

import (
	"encoding/json"
	"fmt"
)

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
// （ip/eth/vlan/mpls/pppoe/tcp/udp）是承载骨架，不算用户意图；gre/tls/
// http/dns 等用户协议层才算。全链都是骨架（独立 [ip→tcp] 传输 flow）
// 时回退末层。
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
		if err := r.ValidateLayerConfig(chain[i]); err != nil {
			return "", err
		}
	}
	for i := range completed {
		if err := r.ValidateLayerConfig(completed[i]); err != nil {
			return "", err
		}
	}

	// V10 + 推断：protocol 必须等于最外层协议层（非脚手架层）。
	outermost := outermostProtocol(completed)
	if protocol != "" {
		if outermost != protocol {
			return "", errf("layers: protocol %q does not match outermost layer %q", protocol, outermost)
		}
		return protocol, nil // 显式 protocol 原样返回（调用方仅 protocol=="" 时回填）
	}
	return outermost, nil
}

// outermostProtocol resolves the strategy's protocol from a completed chain:
// the outermost layer that is not L3/L2/transport scaffolding (承载骨架，
// §6.1 完整示例 [ip, gre, ip, tcp, http] + protocol "gre")。全链都是骨架
// （独立 [ip→tcp] 传输 flow）时回退末层。
func outermostProtocol(completed []Layer) string {
	for i := range completed {
		switch completed[i].Name {
		case "ip", "eth", "vlan", "mpls", "pppoe", "tcp", "udp":
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
