package schema

import (
	"strings"
	"testing"
)

// Step 1（全协议扁平删除）：全体协议顶层 src_ip/dst_ip/src_port/dst_port/count
// 任一出现 → create/update 即 400。ftp 走原 CheckFTPFlat 文案（锁死）；
// 其余协议走通用迁移指引文案。replay 模式不走此门（回放只收 pcap 键）。
func TestProtoFlatRejection(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		config   map[string]any
		wantSub  string
	}{
		{
			name:     "sip flat src_ip",
			protocol: "sip",
			config:   map[string]any{"src_ip": "10.0.0.1", "sip": map[string]any{}},
			wantSub:  "no longer accepts flat config field src_ip",
		},
		{
			name:     "sip flat count",
			protocol: "sip",
			config:   map[string]any{"count": float64(1)},
			wantSub:  "no longer accepts flat config field count",
		},
		{
			name:     "smb flat src_port",
			protocol: "smb",
			config:   map[string]any{"src_port": float64(12345)},
			wantSub:  "no longer accepts flat config field src_port",
		},
		{
			name:     "mqtt flat dst_ip",
			protocol: "mqtt",
			config:   map[string]any{"dst_ip": "20.0.0.1"},
			wantSub:  "no longer accepts flat config field dst_ip",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := ValidateStrategy("synth", tc.protocol, tc.config, nil)
			if len(errs) == 0 {
				t.Fatalf("want flat-%s rejection, got clean", tc.protocol)
			}
			if !strings.Contains(errs.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, errs)
			}
		})
	}
}

// 通用文案同样给迁移指引（层链形状），不是裸拒绝。
func TestProtoFlatRejectionMessageAnchors(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{"src_port": float64(12001)}, nil)
	if len(errs) == 0 {
		t.Fatal("want rejection")
	}
	msg := errs[0].Message
	for _, anchor := range []string{"ip.src/ip.dst", "src_port/dst_port", "flow_control"} {
		if !strings.Contains(msg, anchor) {
			t.Errorf("message missing anchor %q: %s", anchor, msg)
		}
	}
}

// 纯扁平的拒绝必须先于 static copy 文案（flows>1 时 checkStaticCopy 也会触发）。
func TestProtoFlatBeatsStaticCopyMessage(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip",
		map[string]any{"src_port": float64(12345)},
		&FlowControl{Type: "flows", Value: 2})
	if len(errs) == 0 {
		t.Fatal("want rejection")
	}
	if got := errs[0].Message; !strings.Contains(got, "no longer accepts flat config field") {
		t.Fatalf("first error must be the flat rejection, got %q", got)
	}
}

// 顶层同名子映射是现行协议配置载体，不拦（各协议 P-PIPE 改写时才迁入层内）。
func TestProtoFlat_SubConfigAllowed(t *testing.T) {
	_, errs := ValidateStrategy("synth", "mqtt", map[string]any{"mqtt": map[string]any{}}, nil)
	if len(errs) != 0 {
		t.Fatalf("top-level sub-config must stay allowed, got %v", errs)
	}
}

// replay 模式不走此门。
func TestProtoFlat_ReplayExempt(t *testing.T) {
	_, errs := ValidateStrategy("replay", "", map[string]any{"pcap_asset_id": "x"}, &FlowControl{Type: "time", Value: 10})
	if len(errs) != 0 {
		t.Fatalf("replay must stay clean, got %v", errs)
	}
}

// ftp 文案锁死：泛化后 ftp 的拒绝文案与原来逐字一致。
func TestProtoFlat_FTPMessageLocked(t *testing.T) {
	_, errs := ValidateStrategy("synth", "ftp", map[string]any{"src_ip": "10.0.0.1"}, nil)
	if len(errs) == 0 {
		t.Fatal("want rejection")
	}
	if got := errs[0].Message; !strings.Contains(got, "protocol ftp no longer accepts flat config field src_ip") {
		t.Fatalf("ftp message must stay locked, got %q", got)
	}
}
