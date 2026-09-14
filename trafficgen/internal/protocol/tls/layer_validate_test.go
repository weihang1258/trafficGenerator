package tls

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// D-TLS-1 步骤 0①（failing 先行，直调 validator 口径——http
// layer_gen_test.go:151 同款）：零值 TCP 进 validateTLSSpec 后，
// Handshake/Termination 必须被 pin true（mqtt/D-HTTP-1 范式：链上握手/
// 挥手不可关——worker 的防御性补建产物 spec.TCP 零值 false 若不校准，
// tcp 层生成器跳过 SYN/FIN）。当前无 validator：本测试在实现前红
// （validateTLSSpec 未定义 → 编译红；定义后未 pin → 断言红）。
//
// 注意：直调 validator，不走 BuildLayersPlanner——裸 `[{"tls":{}}]` 不是
// 合法建链输入（隧道层不能当末层，V4/V5 拒；合法最小形是
// `[{"tls":{}},{"http":{}}]`，T13 既有形）。
func TestTLSValidator_PinsHandshakeOnZeroValueTCP(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 443,
		TCP: &core.TCPConfig{}, // 模拟 worker 防御性补建产物：零值（false/false）
	}
	if err := validateTLSSpec(&spec); err != nil {
		t.Fatalf("validateTLSSpec: %v", err)
	}
	if spec.TCP == nil || !spec.TCP.Handshake || !spec.TCP.Termination {
		t.Errorf("validator did not pin handshake/termination on zero-value TCP (got %+v)", spec.TCP)
	}
}

// D-TLS-1 步骤 0①（第二红例）：SNI 超长（254 字节）进 validator 必须
// 拒绝——legacy Validate 口径（RFC 1035 上限 253）。链结构性校验
// （chain_planner.go:221，对层 config）守另一边；本测试钉 validator
// 落点（对 spec.TLS 的 legacy 语义检查）。
func TestTLSValidator_SNITooLongRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 443,
		TLS: &core.TLSConfig{SNI: strings.Repeat("a", 254)},
	}
	if err := validateTLSSpec(&spec); err == nil {
		t.Error("validateTLSSpec accepted 254-byte SNI, want rejection (RFC 1035 max 253)")
	}
}

// D-TLS-1 步骤 0①（第三红例）：非法版本字面进 validator 必须拒绝
// （legacy Validate 版本枚举：tls1.0/1.1/1.2/1.3 四者之外全拒）。
func TestTLSValidator_InvalidVersionRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 443,
		TLS: &core.TLSConfig{Version: "tls9.9"},
	}
	if err := validateTLSSpec(&spec); err == nil {
		t.Error("validateTLSSpec accepted invalid version tls9.9, want rejection")
	}
}
