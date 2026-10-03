package schema

import (
	"strings"
	"testing"
)

// Task 5（扁平删除，FTP 层链收尾计划）：protocol==ftp（含 layers 推断的
// effective==ftp）时，顶层 src_ip/dst_ip/src_port/dst_port/count 或顶层 ftp
// 子映射任一出现 → create/update 即 400。FTP 唯一合法形状是层级链
// [ip,tcp,ftp]（kingbase 同构）。
func TestFTPFlatRejection(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		config   map[string]any
		wantSub  string
	}{
		{
			name:     "flat src_ip",
			protocol: "ftp",
			config:   map[string]any{"src_ip": "10.0.0.1", "ftp": map[string]any{"banner": "220"}},
			wantSub:  "rejects flat config field src_ip",
		},
		{
			name:     "flat dst_ip",
			protocol: "ftp",
			config:   map[string]any{"dst_ip": "20.0.0.1"},
			wantSub:  "rejects flat config field dst_ip",
		},
		{
			name:     "flat src_port",
			protocol: "ftp",
			config:   map[string]any{"src_port": float64(21000)},
			wantSub:  "rejects flat config field src_port",
		},
		{
			name:     "flat dst_port",
			protocol: "ftp",
			config:   map[string]any{"dst_port": float64(21)},
			wantSub:  "rejects flat config field dst_port",
		},
		{
			name:     "flat count",
			protocol: "ftp",
			config:   map[string]any{"count": float64(1)},
			wantSub:  "rejects flat config field count",
		},
		{
			name:     "top-level ftp sub-config",
			protocol: "ftp",
			config:   map[string]any{"ftp": map[string]any{"banner": "220 ready"}},
			wantSub:  "top-level ftp sub-config",
		},
		{
			// layers 推断 effective==ftp：protocol 留空、链末层 ftp，
			// 顶层 ftp 键混用同样拒绝（checkLayerFlatConflict 只看四元组键，
			// 顶层 ftp 键由本检查接管）。
			name:     "layers-inferred ftp + top-level ftp sub-config",
			protocol: "",
			config: map[string]any{
				"layers": []any{
					map[string]any{"ip": map[string]any{"src": "10.0.0.1", "dst": "20.0.0.1"}},
					map[string]any{"tcp": map[string]any{"src_port": float64(21000), "dst_port": float64(21)}},
					map[string]any{"ftp": map[string]any{}},
				},
				"ftp": map[string]any{"banner": "220 ready"},
			},
			wantSub: "top-level ftp sub-config",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := ValidateStrategy("synth", tc.protocol, tc.config, nil)
			if len(errs) == 0 {
				t.Fatalf("want flat-ftp rejection, got clean")
			}
			if !strings.Contains(errs.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, errs)
			}
		})
	}
}

// 文案锚点：迁移指引必须点名层链形状（与 checkLayerFlatConflict 家族同款
// 的"给迁移指引"约定），不是裸拒绝。
func TestFTPFlatRejectionMessageAnchors(t *testing.T) {
	_, errs := ValidateStrategy("synth", "ftp", map[string]any{"src_port": float64(21000)}, nil)
	if len(errs) == 0 {
		t.Fatal("want rejection")
	}
	msg := errs[0].Message
	for _, anchor := range []string{"ip.src/ip.dst", "src_port/dst_port", "flow_control"} {
		if !strings.Contains(msg, anchor) {
			t.Errorf("message missing anchor %q: %s", anchor, msg)
		}
	}

	_, errs2 := ValidateStrategy("synth", "ftp", map[string]any{"ftp": map[string]any{"banner": "220"}}, nil)
	if len(errs2) == 0 {
		t.Fatal("want rejection (top-level ftp key)")
	}
	if !strings.Contains(errs2[0].Message, "[ip,tcp,ftp]") {
		t.Errorf("ftp-key message missing layer chain guidance: %s", errs2[0].Message)
	}
}

// 纯扁平 ftp 的拒绝必须先于 static copy 文案（flows>1 时 checkStaticCopy
// 也会触发；flat 判死语境下 "Omit src_port (auto-increment)" 是错误指引，
// 正确指引是迁层链）。
func TestFTPFlatBeatsStaticCopyMessage(t *testing.T) {
	_, errs := ValidateStrategy("synth", "ftp",
		map[string]any{"src_port": float64(12345), "ftp": map[string]any{"commands": []any{}}},
		&FlowControl{Type: "flows", Value: 2})
	if len(errs) == 0 {
		t.Fatal("want rejection")
	}
	if got := errs[0].Message; !strings.Contains(got, "rejects flat config field") {
		t.Fatalf("first error must be the flat rejection, got %q", got)
	}
}

// 层链形状（无任何顶层扁平键）不受影响：最小 [ip,tcp,ftp] 链照常通过。
func TestFTPChainClean(t *testing.T) {
	proto, errs := ValidateStrategy("synth", "", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]any{"tcp": map[string]any{"src_port": float64(21000), "dst_port": float64(21)}},
			map[string]any{"ftp": map[string]any{"banner": "220 chain"}},
		},
	}, nil)
	if len(errs) != 0 {
		t.Fatalf("layer-chain ftp must stay clean, got %v", errs)
	}
	if proto != "ftp" {
		t.Fatalf("inferred protocol = %q, want ftp", proto)
	}
}
