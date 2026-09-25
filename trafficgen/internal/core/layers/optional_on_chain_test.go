package layers

import "testing"

// ---- 红例先行（failing test first）：OptionalOn 在链路校验中的终结层豁免 ----
//
// 背景：schema.go:93 声明 OptionalOn = "可选底座：本层 MAY 坐在这些层之上，
// 系统永不自动插入，只有用户显式写才启用"。但 validateChain 的终结层计数
// 只认 DependsOn（dependedOn 只查 s.DependsOn），OptionalOn 零消费点 ——
// 于是声明了 `OptionalOn ["http"]` 的层在 [ip,tcp,http,X] 链里被当成
// "第二个终结层"，报 duplicated 拒绝。声明与实现不一致。
//
// 影响面：ocsp/spnego/ntlm 三个协议的双 profile（裸 TCP + HTTP）都撞这条。
// 修法：dependedOn 同时认 OptionalOn（底座关系），使显式写了底座层的链
// 可达。对存量零影响——现有 OptionalOn 值只有 tls/eth（隧道/L2），
// 无终结层声明 http，判定不变。

// TestValidateChain_OptionalOnBaseSatisfiesTerminalExemption 是本次修复的
// 红例：X 声明 DependsOn ["tcp"] + OptionalOn ["http"]，链 [ip,tcp,http,X]
// 中 http 应被视为 X 的（可选）底座而豁免终结层计数 → 合法。
func TestValidateChain_OptionalOnBaseSatisfiesTerminalExemption(t *testing.T) {
	r := NewRegistry()
	for _, s := range []LayerSchema{
		{Name: "ip", Category: CategoryNetwork},
		{Name: "tcp", Category: CategoryTransport},
		{Name: "http", Category: CategoryTerminal, DependsOn: []string{"tcp"}, TransformEvents: true},
		{Name: "xproto", Category: CategoryTerminal, DependsOn: []string{"tcp"}, OptionalOn: []string{"http"}},
	} {
		if err := r.Register(s); err != nil {
			t.Fatal(err)
		}
	}
	out, err := r.CompleteChain([]Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "http"}, {Name: "xproto"}})
	if err != nil {
		t.Fatalf("OptionalOn [http] 链应合法（http 是 xproto 的可选底座），got error: %v", err)
	}
	if got := join(out); got != "ip → tcp → http → xproto" {
		t.Fatalf("chain = %q, want %q", got, "ip → tcp → http → xproto")
	}
}

// 反例守恒：不声明 OptionalOn 的层挂在 http 之后仍是第二个终结层 → 拒。
// （T18 的 [ip,tcp,http,dns] 判 duplicated 语义不得被本次修复放宽。）
func TestValidateChain_NoOptionalOnStillDuplicate(t *testing.T) {
	r := NewRegistry()
	for _, s := range []LayerSchema{
		{Name: "ip", Category: CategoryNetwork},
		{Name: "tcp", Category: CategoryTransport},
		{Name: "http", Category: CategoryTerminal, DependsOn: []string{"tcp"}, TransformEvents: true},
		{Name: "yproto", Category: CategoryTerminal, DependsOn: []string{"tcp"}}, // 无 OptionalOn
	} {
		if err := r.Register(s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.CompleteChain([]Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "http"}, {Name: "yproto"}}); err == nil {
		t.Fatal("未声明 OptionalOn 的层挂在 http 之后应判 duplicated，got nil")
	}
}
