package core

// D-DOIP-1（P4）：doip 层 config 的导出解析单一真相。
//
// parseDoIPConfig（strategy_convert.go）是扁平路径 cfg["doip"] 的解析器；
// 层链路径（layers.translateTerminalConfig case "doip"）必须复用同一函数，
// 否则两条路径字段语义分叉（oem_specific/user_data 等字节片的
// getByteSlice/getHexBytes 双语义 + nack_code 指针三态 + has_sub_function
// 指针三态——JSON 往返会误读；srv6 inner_payload/tftp data_payload_pattern
// 同陷阱；dns/http/ftp/ldap/tftp 先例：导出 Parse*FromMap）。

// ParseDoIPConfigFromMap decodes a doip layer/terminal config map into a
// *DoIPConfig. Single truth shared by mapToFlowSpec's flat path and the
// layer-chain translation path; nil input yields nil.
func ParseDoIPConfigFromMap(m map[string]interface{}) *DoIPConfig {
	return parseDoIPConfig(m)
}
