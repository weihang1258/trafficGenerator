package core

import "encoding/json"

// D-IGMP-1（P4）：igmp 层 config 的导出解析单一真相。
//
// 扁平路径（strategy_convert.go case "igmp"）与层链路径
// （layers.translateTerminalConfig case "igmp"）必须复用同一函数，否则两条
// 路径字段语义分叉（tftp/dns/http 先例：导出 Parse*FromMap）。解码语义与
// parseSubconfigJSON 逐字一致：json.Marshal → json.Unmarshal，**普通
// Unmarshal（无 DisallowUnknownFields）**——未知键静默忽略是当前框架共享面
// （G-IGMP-4，跨协议，不在本车道修）；类型不匹配（如数值型 record_type）
// 仍是解码错误，负例 #23 依赖此通道。
//
// ParseIGMPConfigFromMap decodes an igmp layer/terminal config map into a
// *IGMPConfig. nil input yields (nil, nil).
func ParseIGMPConfigFromMap(m map[string]interface{}) (*IGMPConfig, error) {
	if m == nil {
		return nil, nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var cfg IGMPConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
