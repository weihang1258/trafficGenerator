package core

import (
	"strings"
	"testing"
)

// Task 5（扁平删除）：mapToFlowSpec 对 protocol==ftp 的扁平配置判死——
// 在库旧策略（扁平形状入库、create 时尚无此检查）经任务启动路径走到
// mapToFlowSpec 时产生 ValidationErrors，worker 预检（worker.go:210）终态
// error "validation failed: ..."。与 schema 层 400 同条件、同文案。
func TestMapToFlowSpec_FTP_FlatRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
	}{
		{"src_ip", map[string]interface{}{"src_ip": "10.0.0.1"}},
		{"dst_ip", map[string]interface{}{"dst_ip": "20.0.0.1"}},
		{"src_port", map[string]interface{}{"src_port": float64(21000)}},
		{"dst_port", map[string]interface{}{"dst_port": float64(21)}},
		{"count", map[string]interface{}{"count": float64(1)}},
		{"top-level ftp", map[string]interface{}{"ftp": map[string]interface{}{"banner": "220"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := mapToFlowSpec(tc.cfg, "ftp")
			if len(spec.ValidationErrors) == 0 {
				t.Fatalf("flat ftp config must produce ValidationErrors, got clean (cfg=%v)", tc.cfg)
			}
			joined := strings.Join(spec.ValidationErrors, "; ")
			if !strings.Contains(joined, "no longer accepts") {
				t.Fatalf("error must carry the flat-deletion message, got %q", joined)
			}
		})
	}
}

// 层链形状（无顶层扁平键）不触发：strategy 入库的 effective protocol 是
// "ftp"，链上配置照常转换。
func TestMapToFlowSpec_FTP_ChainConfigClean(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": float64(21000), "dst_port": float64(21)}},
			map[string]interface{}{"ftp": map[string]interface{}{"banner": "220 chain"}},
		},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("layer-chain ftp config must stay clean, got %v", spec.ValidationErrors)
	}
}

// 非 ftp 协议不受影响（顶层 ftp 键对 tftp 的 V20 互斥检查仍由 planner 负责）。
func TestMapToFlowSpec_FTP_OtherProtocolsUnaffected(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{"src_ip": "10.0.0.1"}, "tcp")
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("tcp flat config must stay clean, got %v", spec.ValidationErrors)
	}
}

// CheckFTPFlat 是 schema 层与 mapToFlowSpec 共用的判死条件（单一真相，
// 文案不漂移）：nil 键不算出现（JSON null = 缺省）。
func TestCheckFTPFlat(t *testing.T) {
	if msg := CheckFTPFlat(map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1", "src_port": float64(1), "dst_port": float64(2), "count": float64(3)}); !strings.Contains(msg, "src_ip") {
		t.Fatalf("src_ip must be the first reported key, got %q", msg)
	}
	if msg := CheckFTPFlat(map[string]interface{}{"ftp": map[string]interface{}{}}); !strings.Contains(msg, "top-level ftp sub-config") {
		t.Fatalf("ftp key must report the sub-config message, got %q", msg)
	}
	if msg := CheckFTPFlat(map[string]interface{}{"src_ip": nil, "ftp": nil}); msg != "" {
		t.Fatalf("nil keys are absent values, want no message, got %q", msg)
	}
	if msg := CheckFTPFlat(map[string]interface{}{"layers": []interface{}{}}); msg != "" {
		t.Fatalf("chain shape must stay clean, got %q", msg)
	}
	if msg := CheckFTPFlat(nil); msg != "" {
		t.Fatalf("nil config, want no message, got %q", msg)
	}
}
