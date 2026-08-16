package core

import (
	"encoding/json"
	"testing"
)

// TestMapToFlowSpecSMBPortDefault covers the SMB dst_port default
// (design §6 transport: direct=445 / netbios=139). T262/T262b 复现:
// strategy_convert 原实现忽略 transport 字段硬编码 445,导致
// transport=netbios 仍映射到 445 端口,违反 MS-SMB2 §1.5。
func TestMapToFlowSpecSMBPortDefault(t *testing.T) {
	cases := []struct {
		name      string
		transport string
		explicit  interface{} // user-provided dst_port, nil=absent
		wantPort  uint16
	}{
		{"direct default", "", nil, 445},
		{"explicit direct", "direct", nil, 445},
		{"netbios default", "netbios", nil, 139},
		{"netbios + explicit 445", "netbios", float64(445), 445},
		{"direct + explicit 139", "direct", float64(139), 139},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := map[string]interface{}{}
			if tc.transport != "" {
				cfg["smb"] = map[string]interface{}{"transport": tc.transport}
			}
			if tc.explicit != nil {
				cfg["dst_port"] = tc.explicit
			}
			spec := mapToFlowSpec(cfg, "smb")
			if spec.DstPort != tc.wantPort {
				t.Errorf("DstPort = %d, want %d (transport=%q, explicit=%v)",
					spec.DstPort, tc.wantPort, tc.transport, tc.explicit)
			}
		})
	}
}

// TestParseSMBConfigErrorInjection verifies that parseSMBConfig carries
// error_on_command / error_response_status into the SMBConfig (design §4.2
// error-injection table). T129 复现: 经 MCP 的 ErrorOnCommand 曾静默丢弃,
// CREATE 错误注入不生效。
//
// 覆盖三种 JSON 编码路径:
//   - float64 (默认 JSON 解码)
//   - json.Number (UseNumber 路径)
//   - 十六进制字符串 "0xC0000034" (MCP pcap 用例 smb_terr129 的真实编码;
//     getUint32 曾只接受 float64/json.Number, 字符串走 default 返回 0,
//     触发 validate V31 "must be non-zero", planner 不运行 → 0 字节 pcap)
func TestParseSMBConfigErrorInjection(t *testing.T) {
	cases := []struct {
		name string
		val  interface{}
	}{
		{"float64", float64(0xC0000034)}, // STATUS_OBJECT_NAME_NOT_FOUND
		{"json.Number", json.Number("3221225524")},
		{"hex_string", "0xC0000034"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]interface{}{
				"error_on_command":      "create",
				"error_response_status": tc.val,
			}
			cfg := parseSMBConfig(m)
			if cfg == nil {
				t.Fatalf("parseSMBConfig returned nil")
			}
			if cfg.ErrorOnCommand != "create" {
				t.Errorf("ErrorOnCommand = %q, want %q", cfg.ErrorOnCommand, "create")
			}
			if cfg.ErrorResponseStatus != 0xC0000034 {
				t.Errorf("ErrorResponseStatus = 0x%X, want 0xC0000034", cfg.ErrorResponseStatus)
			}
		})
	}
}
