package schema

import (
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

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
		if err := layers.DefaultRegistry().ValidateLayerConfig(layers.Layer{Name: name, Config: lcm}); err != nil {
			return err.Error()
		}
	}
	return ""
}
