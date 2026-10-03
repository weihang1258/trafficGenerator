package http

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "http" {
		t.Errorf("Name() = %s, want http", p.Name())
	}
}

func TestPlanner_Validate(t *testing.T) {
	p := NewPlanner()

	tests := []struct {
		name    string
		spec    core.FlowSpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: core.FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: false,
		},
		{
			name: "invalid source IP",
			spec: core.FlowSpec{
				SrcIP:   "invalid",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPlanner_Plan(t *testing.T) {
	p := NewPlanner()

	spec := core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		HTTP: &core.HTTPConfig{
			Method: "GET",
			URI:    "/api/test",
		},
	}

	configChan, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	var configs []core.PacketConfig
	for config := range configChan {
		configs = append(configs, config)
	}

	// Should have: SYN, SYN-ACK, ACK, HTTP Request, HTTP Response, FIN, ACK, FIN, ACK
	if len(configs) < 9 {
		t.Errorf("Expected at least 9 configs, got %d", len(configs))
	}

	// Check first packet is SYN
	if configs[0].L4.Flags != 0x02 {
		t.Errorf("First packet should be SYN, flags = %x", configs[0].L4.Flags)
	}
}

func TestBuildHTTPRequest(t *testing.T) {
	tests := []struct {
		name     string
		config   *core.HTTPConfig
		contains []string
	}{
		{
			name: "GET request",
			config: &core.HTTPConfig{
				Method: "GET",
				URI:    "/api/test",
			},
			contains: []string{"GET /api/test HTTP/1.1", "Host:"},
		},
		{
			name: "POST request with body",
			config: &core.HTTPConfig{
				Method: "POST",
				URI:    "/api/data",
				Body:   `{"key":"value"}`,
			},
			contains: []string{"POST /api/data HTTP/1.1", "Content-Length:", `{"key":"value"}`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildHTTPRequest(tt.config, "10.0.0.2")
			for _, s := range tt.contains {
				if !containsString(request, s) {
					t.Errorf("Request should contain %s, got: %s", s, request)
				}
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// 无 body 的 keep-alive 响应必须自带 Content-Length: 0（RFC 7230 §3.3.3：
// 无 CL/chunked 时响应边界只能靠连接关闭——keep-alive 流上客户端与
// Wireshark 都无法定界逐条响应，用户实测 Wireshark 全部解不出）。
func TestBuildHTTPResponse_EmptyBodyHasContentLength(t *testing.T) {
	config := &core.HTTPConfig{Version: "HTTP/1.1", ResponseStatusCode: 200, KeepAlive: true}
	resp := buildHTTPResponse(config)
	if !strings.Contains(resp, "Content-Length: 0\r\n") {
		t.Errorf("bodyless keep-alive response missing Content-Length: 0:\n%q", resp)
	}
	// 有 body 时 CL 仍按 body 长度。
	config2 := &core.HTTPConfig{Version: "HTTP/1.1", ResponseStatusCode: 200, ResponseBody: "hello"}
	resp2 := buildHTTPResponse(config2)
	if !strings.Contains(resp2, "Content-Length: 5\r\n") {
		t.Errorf("body response CL wrong:\n%q", resp2)
	}
}
