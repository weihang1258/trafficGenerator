package schema

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// batchDynHint 批量语境的动态对象指引（D-ROBUST-2 N3）：批量 = 单流 ×
// flow_count 包复制，逐流变化（动态对象）属策略入口能力。通用文案
// "validated via ValidateLayers" 会让批量用户迷路（复测回执实测）。
func batchDynHint(layer, field string) string {
	return fmt.Sprintf("batch classes replicate a single flow (flow_count = packet count): dynamic per-flow variation (dynamic objects) belongs to the single-task strategy entry (layer %q field %q)", layer, field)
}

// hasDynObject reports whether a layer config carries a top-level dynamic
// object (strategy-keyed map) — same shape ValidateLayerConfig's scalar gate
// matches.
func hasDynObject(cfg map[string]any) bool {
	for _, v := range cfg {
		if m, ok := v.(map[string]any); ok {
			if _, dyn := m["strategy"]; dyn {
				return true
			}
		}
	}
	return false
}

// ValidateBatchClassLayerFields runs the per-layer field gate (V9 numeric
// ranges / unknown fields / declared-type shape) over a batch class config —
// D-ROBUST-2（客户端复测 N1）：同一非法配置单任务入口建单即拒、批量入口却
// 受理（校验分叉）。本闸给批量入口对齐字段级校验。
//
// 刻意不做两件事：
//   - 策略路径的静态四元组守卫（12.9）不适用——batch 的 flows=N 本就是
//     CORE_MEMORY §2.5 明批的"同模板复制 N 条流"入口（tuples 框架自带逐流
//     变化机制），静态四元组在此是显式复制语义；
//   - 不强制层链唯一形——batch 类的扁平协议子映射（{"tcp":{...}}）是既有
//     合法形状，形状自由不动，只对注册层名做字段面把关。
func ValidateBatchClassLayerFields(config map[string]any) string {
	if config == nil {
		return ""
	}
	if rawLayers, ok := config["layers"].([]any); ok {
		for _, item := range rawLayers {
			lm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			for name, lc := range lm {
				lcm, _ := lc.(map[string]any)
				if lcm == nil {
					continue
				}
				if hasDynObject(lcm) {
					return batchDynHint(name, firstDynField(lcm))
				}
				if err := layers.DefaultRegistry().ValidateLayerConfig(layers.Layer{Name: name, Config: lcm}); err != nil {
					return err.Error()
				}
			}
		}
		return ""
	}
	// 扁平协议子映射形：仅对命中注册层的键同源把关（其余遗留键不动）。
	for name, lc := range config {
		if _, ok := layers.DefaultRegistry().Get(name); !ok {
			continue
		}
		lcm, _ := lc.(map[string]any)
		if lcm == nil {
			continue
		}
		if hasDynObject(lcm) {
			return batchDynHint(name, firstDynField(lcm))
		}
		if err := layers.DefaultRegistry().ValidateLayerConfig(layers.Layer{Name: name, Config: lcm}); err != nil {
			return err.Error()
		}
	}
	return ""
}

func firstDynField(cfg map[string]any) string {
	for f, v := range cfg {
		if m, ok := v.(map[string]any); ok {
			if _, dyn := m["strategy"]; dyn {
				return f
			}
		}
	}
	return ""
}
