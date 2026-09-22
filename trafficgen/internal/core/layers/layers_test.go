package layers

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---- 测试辅助 ----

// names extracts layer names from a chain.
func names(chain []Layer) []string {
	out := make([]string, len(chain))
	for i, l := range chain {
		out[i] = l.Name
	}
	return out
}

func join(chain []Layer) string { return strings.Join(names(chain), " → ") }

func mustComplete(t *testing.T, r *Registry, chain []Layer) []Layer {
	t.Helper()
	out, err := r.CompleteChain(chain)
	if err != nil {
		t.Fatalf("CompleteChain(%v) unexpected error: %v", names(chain), err)
	}
	return out
}

func mustError(t *testing.T, r *Registry, chain []Layer, contains string) {
	t.Helper()
	_, err := r.CompleteChain(chain)
	if err == nil {
		t.Fatalf("CompleteChain(%v) expected error containing %q, got nil", names(chain), contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("CompleteChain(%v) error %q does not contain %q", names(chain), err.Error(), contains)
	}
}

// ---- T1: 层注册表 ----

func TestRegistry_AllSchemasRegistered(t *testing.T) {
	r := DefaultRegistry()
	for _, name := range []string{"eth", "vlan", "tcp", "udp", "http", "dns", "ftp", "smtp", "tls", "gre", "mpls", "pppoe", "ip"} {
		if !r.Has(name) {
			t.Errorf("registry missing layer %q", name)
		}
	}
}

func TestRegistry_DependsOnReferencesResolve(t *testing.T) {
	// init() panics on dangling depends_on; this test re-checks via List.
	r := DefaultRegistry()
	for _, name := range r.List() {
		s, _ := r.Get(name)
		for _, dep := range append(append([]string{}, s.DependsOn...), s.InnerRequired...) {
			if !r.Has(dep) {
				t.Errorf("schema %q references unknown layer %q", name, dep)
			}
		}
	}
}

func TestRegistry_FieldDefaults(t *testing.T) {
	r := DefaultRegistry()
	cases := []struct {
		layer, field string
		want         interface{}
	}{
		{"tcp", "mss", uint16(1460)},
		{"tcp", "window_size", uint16(65535)},
		{"tcp", "handshake", true},
		{"http", "method", "GET"},
		{"http", "uri", "/"},
		{"http", "version", "1.1"},
		{"dns", "query_type", uint16(1)},
		{"tls", "version", "tls1.3"},
		{"gre", "checksum", false},
	}
	for _, tc := range cases {
		s, ok := r.Get(tc.layer)
		if !ok {
			t.Errorf("layer %q missing", tc.layer)
			continue
		}
		f, ok := s.Fields[tc.field]
		if !ok {
			t.Errorf("layer %q field %q missing", tc.layer, tc.field)
			continue
		}
		if f.Default != tc.want {
			t.Errorf("layer %q field %q default = %v (%T), want %v (%T)",
				tc.layer, tc.field, f.Default, f.Default, tc.want, tc.want)
		}
	}
}

func TestRegistry_FieldBounds(t *testing.T) {
	// 显式 0 ≠ 缺失（§6.4）：字段有 Min/Max 边界，0 在范围内（tcp.dst_port 0 合法）。
	r := DefaultRegistry()
	s, _ := r.Get("tcp")
	if f := s.Fields["dst_port"]; f.Min != 0 || f.Max != 65535 {
		t.Errorf("tcp.dst_port bounds = [%d,%d], want [0,65535]", f.Min, f.Max)
	}
	// mss 下限 536（RFC 879）。
	if f := s.Fields["mss"]; f.Min != 536 {
		t.Errorf("tcp.mss Min = %d, want 536", f.Min)
	}
}

// ---- T2/T3/T4: 层链补全 ----

func TestComplete_HTTPEmpty(t *testing.T) {
	// §12.1: {"http":{}} → [ip → tcp → http]
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{{Name: "http"}})
	if got := join(out); got != "ip → tcp → http" {
		t.Fatalf("http empty chain = %q, want %q", got, "ip → tcp → http")
	}
}

func TestComplete_GREHTTP_DoubleIP(t *testing.T) {
	// §12.3: gre + http → [ip → gre → ip → tcp → http]（双层 ip）
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{{Name: "gre"}, {Name: "http"}})
	if got := join(out); got != "ip → gre → ip → tcp → http" {
		t.Fatalf("gre+http chain = %q, want %q", got, "ip → gre → ip → tcp → http")
	}
}

func TestComplete_TLSHandwritten_NoAutoTLS(t *testing.T) {
	// §12.2: tls + http（tls 手写）→ [ip → tcp → tls → http]
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{{Name: "tls"}, {Name: "http"}})
	if got := join(out); got != "ip → tcp → tls → http" {
		t.Fatalf("tls+http chain = %q, want %q", got, "ip → tcp → tls → http")
	}
}

func TestComplete_HTTPNoTLS_OptionalOn(t *testing.T) {
	// T5: 可选底座默认不启用：{"http":{}} 生成 http 非 https。
	// tls 是 http 的 optional_on，系统永不自动补。
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{{Name: "http"}})
	for _, l := range out {
		if l.Name == "tls" {
			t.Fatalf("http empty chain unexpectedly contains tls: %q", join(out))
		}
	}
	if got := join(out); got != "ip → tcp → http" {
		t.Fatalf("http chain = %q, want %q (no tls auto-insert)", got, "ip → tcp → http")
	}
}

func TestComplete_VLANOutermost(t *testing.T) {
	// 双层 vlan：vlan 垫 eth，链首（最外）是 eth。
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{{Name: "vlan"}, {Name: "vlan"}, {Name: "http"}})
	if got := join(out); got != "eth → vlan → vlan → ip → tcp → http" {
		t.Fatalf("double-vlan chain = %q, want %q", got, "eth → vlan → vlan → ip → tcp → http")
	}
}

// ---- T6: 手动配置值 > schema 默认值（同层） ----

func TestManualConfigWins_PreservedThroughCompletion(t *testing.T) {
	// §8: 手动显式配置值 > schema 默认值。补全必须保留用户的层配置。
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1"}},
		{Name: "http", Config: map[string]interface{}{"method": "POST"}},
	})
	// 用户写的 ip 层配置保留。
	for _, l := range out {
		if l.Name == "ip" && l.Config == nil {
			t.Errorf("user ip layer config lost: %+v", out)
		}
		if l.Name == "http" {
			if v, ok := l.Config["method"]; !ok || v != "POST" {
				t.Errorf("user http method lost, got %v", l.Config)
			}
		}
	}
}

// ---- T8: 同层多实例（顺序即身份） ----

func TestMultipleSameLayer_OrderPreserved(t *testing.T) {
	// §5.3: 同层可多次出现，顺序即身份。补全不得打乱用户写的顺序。
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{
		{Name: "vlan", Config: map[string]interface{}{"id": 100}},
		{Name: "vlan", Config: map[string]interface{}{"id": 200}},
		{Name: "http"},
	})
	vlans := []interface{}{}
	for _, l := range out {
		if l.Name == "vlan" {
			vlans = append(vlans, l.Config["id"])
		}
	}
	if len(vlans) != 2 || vlans[0] != 100 || vlans[1] != 200 {
		t.Fatalf("vlan order lost: got %v, want [100 200]", vlans)
	}
}

// ---- T9/T10 + §13.4 负向测试（T16-T22） ----

func TestValidate_EmptyChain(t *testing.T) {
	mustError(t, DefaultRegistry(), nil, "empty layer chain")
}

func TestValidate_UnknownLayer(t *testing.T) {
	mustError(t, DefaultRegistry(), []Layer{{Name: "foo"}}, `unknown layer "foo"`)
}

func TestValidate_TerminalDuplicated(t *testing.T) {
	// V2: 终结层唯一。用 s7（无 TransformEvents 标记的终结层）验证。
	// http 有 TransformEvents=true 豁免，不适用此测试。
	mustError(t, DefaultRegistry(), []Layer{{Name: "s7"}, {Name: "ip"}, {Name: "tcp"}, {Name: "s7"}},
		"terminal layer")
}

func TestValidate_TransportAsLastLayer(t *testing.T) {
	// V5: 传输层不能是末层。
	mustError(t, DefaultRegistry(), []Layer{{Name: "ip"}, {Name: "tcp"}},
		"must end with a terminal layer")
}

func TestValidate_TunnelAsLastLayer(t *testing.T) {
	// V6: 隧道层不能是末层。
	mustError(t, DefaultRegistry(), []Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "tls"}},
		"must end with a terminal layer")
}

func TestValidate_L2NotOutermost(t *testing.T) {
	// V7: 二层层只能出现在链最外的开头连续段。
	// 补全会先插 eth（vlan 的 depends_on），所以校验须用显式补全后的链。
	r := DefaultRegistry()
	// [ip, vlan, http]（未补全）：vlan 不在开头连续段（前面有 ip）→ 报错
	err := r.ValidateChain([]Layer{{Name: "ip"}, {Name: "vlan"}, {Name: "http"}})
	if err == nil || !strings.Contains(err.Error(), "outermost run") {
		t.Fatalf("ip+ip+vlan not rejected: %v", err)
	}
	// 补全后 [eth, vlan, vlan, ip, tcp, http] 合法
	ok := r.ValidateChain([]Layer{{Name: "eth"}, {Name: "vlan"}, {Name: "vlan"}, {Name: "ip"}, {Name: "tcp"}, {Name: "http"}})
	if ok != nil {
		t.Fatalf("valid double-vlan chain rejected: %v", ok)
	}
}

func TestValidate_TerminalMissing(t *testing.T) {
	// 传输层+隧道层无终结层：隧道层当末层报错。
	mustError(t, DefaultRegistry(), []Layer{{Name: "gre"}, {Name: "ip"}, {Name: "tcp"}},
		"must end with a terminal layer")
}

// ---- HIGH-1 回归：末层必须是终结层，ip 结尾也必须拒绝（§10.2 V4）----

func TestValidate_NetworkAsLastLayer(t *testing.T) {
	// ip（CategoryNetwork）当末层：零终结层链必须拒绝。
	// 触发场景：[gre] 补全自产 [ip, gre, ip]（gre 末层 inner_required 补内层 ip），
	// 之前末层 switch 无 network case → 校验通过（补全输出违反 V4 却没被发现）。
	r := DefaultRegistry()
	mustError(t, r, []Layer{{Name: "gre"}}, "must end with a terminal layer")
	// 直接校验零终结层链。
	err := r.ValidateChain([]Layer{{Name: "ip"}, {Name: "ip"}})
	if err == nil || !strings.Contains(err.Error(), "must end with a terminal layer") {
		t.Fatalf("[ip, ip] not rejected: %v", err)
	}
}

// ---- MEDIUM-1 回归：V3 同名传输层重复也必须拒绝（§5.2 规则 2）----

func TestValidate_TransportDuplicatedSameName(t *testing.T) {
	// 两个同名 tcp 是同一层出现两次，V3 要求"全链唯一"，必须拒绝。
	// 之前 transportSeen 按层名去重 → 计为 1 → 放行。
	r := DefaultRegistry()
	mustError(t, r, []Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "tcp"}, {Name: "http"}},
		"transport layer duplicated")
	// 显式两个 tcp + http（补全后 ip 垫底）也拒绝。
	mustError(t, r, []Layer{{Name: "tcp"}, {Name: "tcp"}, {Name: "http"}},
		"transport layer duplicated")
}

// ---- HIGH-1 回归：inner_required 插层后内层依赖也要补（第三趟回看）----

func TestComplete_InnerRequiredPush_DepsRecompleted(t *testing.T) {
	// 构造一条链：foo 依赖 gre（在 gre 内侧），gre 是隧道层（inner_required ip）。
	// 场景：gre 内层是 foo（未满足 inner_required）→ 第二趟在 gre 内侧插 ip，
	//   foo 被推到 ip 更内侧；若没有第三趟回看，foo 缺 gre 未被补 → V8 拒绝。
	// 期望：第三趟补 foo 的 gre 依赖（在 foo 外侧、ip 内侧）→ 校验通过。
	r := NewRegistry()
	if err := r.Register(LayerSchema{Name: "ip", Category: CategoryNetwork}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(LayerSchema{Name: "gre", Category: CategoryTunnel,
		DependsOn:     []string{"ip"}, // 外层 ip（真实 gre 语义）
		InnerRequired: []string{"ip"}, // 内层从 ip 开始
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(LayerSchema{Name: "foo", Category: CategoryTerminal, DependsOn: []string{"gre"}}); err != nil {
		t.Fatal(err)
	}
	out := mustComplete(t, r, []Layer{{Name: "foo"}})
	got := join(out)
	if got != "ip → gre → ip → foo" {
		t.Fatalf("chain = %q, want %q (foo 的 gre 依赖必须在第三趟补上)", got, "ip → gre → ip → foo")
	}
}

// ---- 隧道层 inner_required 边界 ----

func TestValidate_GREInnerNotIP(t *testing.T) {
	// gre 内层直接邻居不是 ip（且无自动补全入口）→ 校验报错。
	// 注意：CompleteChain 会自动补 ip，这里直接调 ValidateChain。
	r := DefaultRegistry()
	// gre 内层是 http（未补全）→ 校验失败
	err := r.ValidateChain([]Layer{{Name: "ip"}, {Name: "gre"}, {Name: "http"}})
	if err == nil || !strings.Contains(err.Error(), "inner") {
		t.Fatalf("gre inner http not rejected: %v", err)
	}
	// 补全后 gre 内层是 ip → 校验通过
	ok := r.ValidateChain([]Layer{{Name: "ip"}, {Name: "gre"}, {Name: "ip"}, {Name: "tcp"}, {Name: "http"}})
	if ok != nil {
		t.Fatalf("valid gre chain rejected: %v", ok)
	}
}

// ---- T7: 显式 0 ≠ 缺失（§6.4）----

func TestTransportOn_ExplicitTCPOverridesUDPMax(t *testing.T) {
	// §4.4 注记：dns 的 depends_on 默认为 udp，用户显式写 tcp 层覆盖
	// （{"dns":{}, "tcp":{}} → [ip → tcp → dns]）。不得重复补 udp。
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{{Name: "tcp"}, {Name: "dns"}})
	if got := join(out); got != "ip → tcp → dns" {
		t.Fatalf("tcp+dns chain = %q, want %q", got, "ip → tcp → dns")
	}
}

func TestTransportOn_ExplicitUDP(t *testing.T) {
	// 用户显式写 udp → [ip → udp → dns]（默认也是 udp，不重复）。
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{{Name: "udp"}, {Name: "dns"}})
	if got := join(out); got != "ip → udp → dns" {
		t.Fatalf("udp+dns chain = %q, want %q", got, "ip → udp → dns")
	}
}

func TestTransportOn_ImplicitDefault(t *testing.T) {
	// 未写任何传输层 → 默认 udp。
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{{Name: "dns"}})
	if got := join(out); got != "ip → udp → dns" {
		t.Fatalf("dns chain = %q, want %q", got, "ip → udp → dns")
	}
}

func TestTransportOn_HTTPRejectsUDP(t *testing.T) {
	// http 只支持 tcp；用户写 udp + http → 传输层唯一冲突 → 报错（http 不走 udp）。
	mustError(t, DefaultRegistry(), []Layer{{Name: "udp"}, {Name: "http"}},
		"transport layer duplicated")
}

func TestTransportOn_ExplicitTwoTransportsRejected(t *testing.T) {
	// 用户显式写两个传输层 → V3 报错（自相矛盾）。
	mustError(t, DefaultRegistry(), []Layer{{Name: "tcp"}, {Name: "udp"}, {Name: "dns"}},
		"transport layer duplicated")
}

// ---- T7: 显式 0 ≠ 缺失（§6.4）----

func TestValidateLayerConfig_ExplicitZeroWithinBounds(t *testing.T) {
	// 显式 0 是合法值（dst_port 0 = 由上层决定，不是错误）。
	r := DefaultRegistry()
	err := r.ValidateLayerConfig(Layer{Name: "tcp", Config: map[string]interface{}{"dst_port": 0}})
	if err != nil {
		t.Fatalf("explicit dst_port=0 rejected: %v", err)
	}
}

func TestValidateLayerConfig_MissingFieldNoError(t *testing.T) {
	// 字段缺失不是错误（走 schema 默认值）。
	r := DefaultRegistry()
	err := r.ValidateLayerConfig(Layer{Name: "tcp"})
	if err != nil {
		t.Fatalf("empty tcp layer rejected: %v", err)
	}
}

func TestValidateLayerConfig_UnknownField(t *testing.T) {
	// 拼写错误字段报错（防 typo）。
	r := DefaultRegistry()
	err := r.ValidateLayerConfig(Layer{Name: "tcp", Config: map[string]interface{}{"window": 100}})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field not rejected: %v", err)
	}
}

// ---- T21: 字段超范围（§10.2 V9）----

func TestValidateLayerConfig_OutOfRange(t *testing.T) {
	r := DefaultRegistry()
	cases := []struct {
		name string
		cfg  map[string]interface{}
	}{
		{"tcp", map[string]interface{}{"mss": 500}},        // min 536（RFC 879）
		{"tcp", map[string]interface{}{"dst_port": 70000}}, // max 65535
		{"vlan", map[string]interface{}{"id": 4096}},       // max 4095
		{"ip", map[string]interface{}{"ttl": 256}},         // max 255
		{"ip", map[string]interface{}{"dscp": 64}},         // max 63
		{"vlan", map[string]interface{}{"priority": 8}},    // max 7
	}
	for _, tc := range cases {
		err := r.ValidateLayerConfig(Layer{Name: tc.name, Config: tc.cfg})
		if err == nil || !strings.Contains(err.Error(), "out of range") {
			t.Errorf("%s %v: not rejected as out-of-range: %v", tc.name, tc.cfg, err)
		}
	}
}

func TestValidateLayerConfig_InRange(t *testing.T) {
	// 边界值合法（min/max 含端点）。
	r := DefaultRegistry()
	cases := []struct {
		name string
		cfg  map[string]interface{}
	}{
		{"tcp", map[string]interface{}{"mss": 536}},        // min
		{"tcp", map[string]interface{}{"dst_port": 65535}}, // max
		{"vlan", map[string]interface{}{"id": 4095}},       // max
		{"ip", map[string]interface{}{"ttl": 255}},         // max
	}
	for _, tc := range cases {
		if err := r.ValidateLayerConfig(Layer{Name: tc.name, Config: tc.cfg}); err != nil {
			t.Errorf("%s %v: boundary value rejected: %v", tc.name, tc.cfg, err)
		}
	}
}

// ---- MEDIUM-2 回归：asInt64 溢出/小数不得绕过 V9 范围检查 ----

func TestValidateLayerConfig_OverflowingNumberRejected(t *testing.T) {
	// json.Number 超 int64（如 2^64-1）必须拒绝，不能静默跳过。
	r := DefaultRegistry()
	err := r.ValidateLayerConfig(Layer{Name: "vlan", Config: map[string]interface{}{
		"id": json.Number("18446744073709551615"),
	}})
	if err == nil {
		t.Fatalf("overflowing vlan id not rejected: %v", err)
	}
	// 拒绝理由是"不可转换"，不是范围（错误文案含 invalid）。
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("overflow rejection reason unclear: %v", err)
	}
}

func TestValidateLayerConfig_FractionalValueRejected(t *testing.T) {
	// 1.5 是小数，对 uint16 字段非法，必须拒绝（不能截断成 1 通过）。
	r := DefaultRegistry()
	err := r.ValidateLayerConfig(Layer{Name: "ip", Config: map[string]interface{}{"ttl": 1.5}})
	if err == nil {
		t.Fatalf("fractional ttl not rejected: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("fractional rejection reason unclear: %v", err)
	}
}

// ---- MEDIUM（CRITICAL-1 同类，对抗 review 发现）：字段值类型不一致必须拒绝 ----
// V9 校验与生成器转换必须同一口径：bool 值（true/false）不能放进数值字段
// （window_size/ttl/mss/port…）——旧实现 asInt64 把 true 当 1 放行，生成器
// configUint64 拒绝，错误被驱动 goroutine 吞掉 → 静默空流（与 CRITICAL-1
// 同类后果）。

func TestValidateLayerConfig_BoolForNumericFieldRejected(t *testing.T) {
	r := DefaultRegistry()
	cases := []struct {
		name string
		cfg  map[string]interface{}
	}{
		{"tcp", map[string]interface{}{"window_size": true}},
		{"tcp", map[string]interface{}{"mss": false}},
		{"ip", map[string]interface{}{"ttl": true}},
	}
	for _, tc := range cases {
		err := r.ValidateLayerConfig(Layer{Name: tc.name, Config: tc.cfg})
		if err == nil {
			t.Errorf("%s %v: bool for numeric field not rejected", tc.name, tc.cfg)
		}
	}
}

// bool 字段（handshake 等）接受 bool 与 "true"/"false" 字符串，不受影响。
func TestValidateLayerConfig_BoolFieldStillAccepted(t *testing.T) {
	r := DefaultRegistry()
	cases := []map[string]interface{}{
		{"handshake": true},
		{"handshake": "true"},
		{"handshake": "false"},
	}
	for _, cfg := range cases {
		if err := r.ValidateLayerConfig(Layer{Name: "tcp", Config: cfg}); err != nil {
			t.Errorf("bool field %v rejected: %v", cfg, err)
		}
	}
}

// ---- protocol 字段与层链最外层一致性（V10，解析层做，这里测接口） ----

func TestOutermostLayer(t *testing.T) {
	// protocol 可省，由层链最外层推断（§6.2）。
	r := DefaultRegistry()
	out := mustComplete(t, r, []Layer{{Name: "gre"}, {Name: "http"}})
	if out[0].Name != "ip" {
		t.Fatalf("outermost layer = %q, want ip", out[0].Name)
	}
}
