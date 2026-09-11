package core

import "testing"

// T-FTP-2 前置 failing test：sessions 形状解析（D-FTP-1 §7 步骤2）。
// Task 5 扁平删除后经 ParseFTPConfigFromMap 驱动（层链 translateTerminalConfig
// 的同一真相）；sessions 形状断言不变。
func TestParseFTPConfig_Sessions(t *testing.T) {
	m := map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"src_port": float64(20000),
				"banner":   "220 s1",
				"transactions": []interface{}{
					map[string]interface{}{
						"commands": []interface{}{
							map[string]interface{}{"cmd": "USER anonymous", "response": "331"},
						},
						"data_channel": map[string]interface{}{"payload": "hello"},
					},
				},
			},
		},
	}
	fc := ParseFTPConfigFromMap(m)
	if fc == nil {
		t.Fatal("fc nil")
	}
	if len(fc.Sessions) != 1 {
		t.Fatalf("Sessions len = %d, want 1 (sessions shape not parsed yet)", len(fc.Sessions))
	}
	s := fc.Sessions[0]
	if s.SrcPort != 20000 || s.Banner != "220 s1" {
		t.Errorf("session0 = %+v", s)
	}
	if len(s.Transactions) != 1 || len(s.Transactions[0].Commands) != 1 {
		t.Errorf("transactions = %+v", s.Transactions)
	}
	if s.Transactions[0].DataChannel == nil || s.Transactions[0].DataChannel.Payload != "hello" {
		t.Errorf("data_channel = %+v", s.Transactions[0].DataChannel)
	}
}
