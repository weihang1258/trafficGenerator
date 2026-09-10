package core

import "testing"

// T-FTP-2 前置 failing test：sessions 形状解析（D-FTP-1 §7 步骤2）。
// Sessions 字段尚未实现，ParseStrategyConfig 应把 ftp.sessions 带进 spec.FTP.Sessions。
func TestParseFTPConfig_Sessions(t *testing.T) {
	cfg := map[string]interface{}{
		"ftp": map[string]interface{}{
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
		},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.FTP == nil {
		t.Fatal("spec.FTP nil")
	}
	if len(spec.FTP.Sessions) != 1 {
		t.Fatalf("Sessions len = %d, want 1 (sessions shape not parsed yet)", len(spec.FTP.Sessions))
	}
	s := spec.FTP.Sessions[0]
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
