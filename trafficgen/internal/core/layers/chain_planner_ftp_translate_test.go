package layers_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Task 2：层内 ftp map → spec.FTP 与扁平 cfg["ftp"] 同输入逐字段相等。
// 翻译走 core.ParseFTPConfigFromMap（与 mapToFlowSpec 同 parse 函数）。
func TestFTPTranslateLayerEqualsFlat(t *testing.T) {
	layerFTP := map[string]interface{}{
		"banner": "220 FTP server ready",
		"commands": []interface{}{
			map[string]interface{}{"cmd": "USER anonymous", "response": "331 ok"},
			map[string]interface{}{"cmd": "RETR /a.bin", "response": "150", "emit_data_channel": true},
			map[string]interface{}{"cmd": "", "response": "226 done"},
		},
		"data_channel": map[string]interface{}{
			"mode": "passive", "direction": "down", "payload": "HELLO",
		},
		"sessions": []interface{}{
			map[string]interface{}{
				"src_port": float64(20000), // JSON 解码数字是 float64（getUint16 口径）
				"banner":   "220 s1",
				"transactions": []interface{}{
					map[string]interface{}{
						"commands": []interface{}{
							map[string]interface{}{"cmd": "QUIT", "response": "221"},
						},
						"data_channel": map[string]interface{}{"payload": "X"},
					},
				},
			},
		},
	}
	// 与扁平 cfg["ftp"] 同 parse 函数（mapToFlowSpec :425 分支），同输入
	// 逐字段相等即零分叉证明。
	fromLayer := core.ParseFTPConfigFromMap(layerFTP)
	if fromLayer == nil {
		t.Fatal("ParseFTPConfigFromMap returned nil for full ftp map")
	}
	if fromLayer.Banner != "220 FTP server ready" {
		t.Errorf("Banner = %q", fromLayer.Banner)
	}
	if len(fromLayer.Commands) != 3 {
		t.Fatalf("Commands = %d, want 3", len(fromLayer.Commands))
	}
	if !fromLayer.Commands[1].EmitDataChannel {
		t.Error("Commands[1].EmitDataChannel = false, want true")
	}
	if fromLayer.DataChannel == nil || fromLayer.DataChannel.Payload != "HELLO" {
		t.Errorf("DataChannel = %+v, want payload HELLO", fromLayer.DataChannel)
	}
	if fromLayer.DataChannel.Mode != "passive" || fromLayer.DataChannel.Direction != "down" {
		t.Errorf("DataChannel mode/dir = %q/%q, want passive/down defaults",
			fromLayer.DataChannel.Mode, fromLayer.DataChannel.Direction)
	}
	if len(fromLayer.Sessions) != 1 {
		t.Fatalf("Sessions = %d, want 1", len(fromLayer.Sessions))
	}
	s0 := fromLayer.Sessions[0]
	if s0.SrcPort != 20000 || s0.Banner != "220 s1" {
		t.Errorf("session0 = port %d banner %q, want 20000/220 s1", s0.SrcPort, s0.Banner)
	}
	if len(s0.Transactions) != 1 || len(s0.Transactions[0].Commands) != 1 {
		t.Fatalf("session0 tx shape wrong: %+v", s0.Transactions)
	}
	if s0.Transactions[0].DataChannel == nil || s0.Transactions[0].DataChannel.Payload != "X" {
		t.Errorf("tx data_channel = %+v, want payload X", s0.Transactions[0].DataChannel)
	}

	// 空 map → nil（生成器对 nil Config 走默认空会话，与 legacy Plan
	// 对 nil FTPConfig 同款）；nil → nil。
	if core.ParseFTPConfigFromMap(map[string]interface{}{}) != nil {
		t.Error("empty map should yield nil (generator defaults on nil)")
	}
	if core.ParseFTPConfigFromMap(nil) != nil {
		t.Error("nil map should yield nil")
	}
}
