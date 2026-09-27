package core

// D-TFTP-1（P4）：tftp 层 config 的导出解析单一真相。
//
// parseTFTPConfig（strategy_convert.go）是扁平路径 cfg["tftp"] 的解析器；
// 层链路径（layers.translateTerminalConfig case "tftp"）必须复用同一函数，
// 否则两条路径字段语义分叉（dns/http/ftp/ldap 先例：导出 Parse*FromMap）。

// ParseTFTPConfigFromMap decodes a tftp layer/terminal config map into a
// *TFTPConfig. Single truth shared by mapToFlowSpec's flat path and the
// layer-chain translation path; nil input yields nil.
func ParseTFTPConfigFromMap(m map[string]interface{}) *TFTPConfig {
	return parseTFTPConfig(m)
}
