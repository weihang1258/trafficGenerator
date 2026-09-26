// Package spnego planner：负例校验（6 wire_fault 一行一注入——设计 §2/
// §12 与用例 §4 三方同序）+ 结构/状态守卫（OID 绑定、reqFlags 位域、
// profile↔载体一致、会话事件顺序、MIC/negHints 槽互斥、端点覆盖）。
// 每个被拒 spec 必须传播为 task error——绝不产出 completed/0-packet 假成功。
//
// 处置表：6 负例两通道——6 全部走 validateWireFault 注入拒（生成路径结构
// 上恒自洽：OID 恒合法合规、长度恒自洽、choice 恒三形内、MIC 恒携带——
// ntlm 同款"生成恒自洽、注入唯一通道"口径）；自然非法配置另走结构守卫
// （profile/negotiation/req_flags/neg_hints/layout/会话顺序/端点覆盖/
// profile↔事件 kind）。
package spnego

import (
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner is the layer-validator entry type (kerberos/dtls/ntlm 同款).
type Planner struct{}

// Validate checks a spnego flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error { return validateSpec(spec) }

// validateSpec: cfg == nil（bare {"spnego":{}} 层或缺键）通过：生成器发一条
// 最小 init 基线（缺省档 tcp——空配置缺省家族同款，裸层不静默 0 包）。
func validateSpec(spec core.FlowSpec) error {
	cfg := spec.SPNEGO
	if cfg == nil {
		return nil
	}
	// 会话级端口冲突守卫（契约 §12 错误分支②）：TCP 载体 = 单流单四元组，
	// 会话 dst_port 覆盖必须与流端口一致（ntlm kindAllowed/session msgID
	// 面同款守卫精神）。
	for si := range cfg.Sessions {
		if p := cfg.Sessions[si].DstPort; p != nil && spec.DstPort != 0 && *p != int(spec.DstPort) {
			return fmt.Errorf("spnego: sessions[%d].dst_port %d conflicts with flow dst_port %d (port)", si, *p, spec.DstPort)
		}
		if ip := strings.TrimSpace(cfg.Sessions[si].SrcIP); ip != "" {
			return fmt.Errorf("spnego: sessions[%d].src_ip override is not supported on the tcp carrier — flow identity is the connection four-tuple (carrier)", si)
		}
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	for si := range cfg.Sessions {
		if err := validateSession(cfg, &cfg.Sessions[si], si); err != nil {
			return err
		}
	}
	return nil
}

// validateConfig 拒未知 profile/negotiation/req_flags/neg_hints/layout 与
// [3] 槽二义（裁定2 ②：同消息同时声明 dissector 形 negHints 与 RFC 形 MIC）。
func validateConfig(cfg *core.SPNEGOConfig) error {
	switch profileOf(cfg) {
	case "tcp", "http":
	default:
		return fmt.Errorf("spnego: unknown profile %q — must be tcp or http (profile)", cfg.Profile)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Negotiation)) {
	case "", "init_resp", "init_targ":
	default:
		return fmt.Errorf("spnego: unknown negotiation %q — must be init_resp or init_targ (sequence)", cfg.Negotiation)
	}
	if cfg.NegResult != nil {
		hi := 3
		if strings.EqualFold(strings.TrimSpace(cfg.Negotiation), "init_targ") {
			hi = 2
		}
		if *cfg.NegResult < 0 || *cfg.NegResult > hi {
			return fmt.Errorf("spnego: neg_result %d out of range 0..%d (neg_result)", *cfg.NegResult, hi)
		}
	}
	if cfg.NegHints != nil {
		switch strings.ToLower(strings.TrimSpace(cfg.NegHints.Carry)) {
		case "", "none", "dissector":
		default:
			return fmt.Errorf("spnego: neg_hints.carry %q is not none or dissector (RFC 形默认；dissector 形走 [3] 槽) (neg_hints)", cfg.NegHints.Carry)
		}
		if strings.EqualFold(strings.TrimSpace(cfg.NegHints.Carry), "dissector") {
			if cfg.NegHints.HintAddress != "" {
				if _, err := hexBytes(cfg.NegHints.HintAddress, "neg_hints.hint_address"); err != nil {
					return err
				}
			}
			if cfg.MechListMIC != nil {
				return fmt.Errorf("spnego: neg_hints.carry=dissector and mech_list_mic share NegTokenInit [3] — declare only one (RFC 4178 §4.2.1 vs dissector layout) (mic)")
			}
		}
	}
	if cfg.MechListMIC != nil {
		switch strings.ToLower(strings.TrimSpace(cfg.MechListMIC.Layout)) {
		case "", "rfc4178":
		default:
			return fmt.Errorf("spnego: mech_list_mic.layout %q is not rfc4178 — only the RFC 4178 [3] layout is produced (layout)", cfg.MechListMIC.Layout)
		}
		if l := micLenOf(cfg.MechListMIC); l < 0 {
			return fmt.Errorf("spnego: mech_list_mic.len %d is negative (length)", *cfg.MechListMIC.Len)
		}
	}
	for _, m := range cfg.MechTypes {
		if _, err := resolveOID(m); err != nil {
			return err
		}
	}
	if cfg.SupportedMech != "" {
		if _, err := resolveOID(cfg.SupportedMech); err != nil {
			return err
		}
		// 降级守卫（契约 §5）：选定机制必须 ∈ 原始候选列表。
		if !containsOID(sessionMechList(cfg), cfg.SupportedMech) {
			return fmt.Errorf("spnego: supported_mech %q is not in the offered mech_types — acceptor must not select an unoffered mechanism (selection)", cfg.SupportedMech)
		}
	}
	if err := checkTokenLen(cfg.MechToken, "mech_token"); err != nil {
		return err
	}
	if err := checkTokenLen(cfg.ResponseToken, "response_token"); err != nil {
		return err
	}
	return nil
}

// sessionMechList 求配置级候选列表（降级守卫的"原始列表"；会话覆盖在
// validateSession 内逐会话守）。
func sessionMechList(cfg *core.SPNEGOConfig) []string {
	if cfg != nil && len(cfg.MechTypes) > 0 {
		return cfg.MechTypes
	}
	return []string{"1.2.840.113554.1.2.2"}
}

func micLenOf(m *core.SPNEGOMIC) int {
	if m == nil || m.Len == nil {
		return 0
	}
	return *m.Len
}

func checkTokenLen(t *core.SPNEGOToken, what string) error {
	if t == nil || t.Len == nil {
		return nil
	}
	if *t.Len < 0 {
		return fmt.Errorf("spnego: %s.len %d is negative (length)", what, *t.Len)
	}
	return nil
}

// containsOID 比规范形（别名→规范 OID 再比）。
func containsOID(list []string, want string) bool {
	wc := canonicalOID(want)
	for _, m := range list {
		if canonicalOID(m) == wc {
			return true
		}
	}
	return false
}

func canonicalOID(text string) string {
	t := strings.TrimSpace(text)
	if canon, ok := oidAlias[strings.ToLower(t)]; ok {
		return canon
	}
	return t
}

// validateSession 逐会话：事件 kind 合法（profile↔kind 一致）+ 状态机顺序 +
// 降级守卫（会话覆盖的选定 OID 也必须 ∈ 该会话候选列表）+ targ 档三值。
// （与 renderEvent 同一权威——校验即生成前置演练，不做第二套规则。）
func validateSession(cfg *core.SPNEGOConfig, sess *core.SPNEGOSession, si int) error {
	profile := profileOf(cfg)
	negotiation := strings.ToLower(strings.TrimSpace(cfg.Negotiation))
	// 会话候选列表：会话覆盖 > 配置级 > 缺省。
	mechs := sess.MechTypes
	if len(mechs) == 0 {
		mechs = sessionMechList(cfg)
	}
	for _, m := range mechs {
		if _, err := resolveOID(m); err != nil {
			return fmt.Errorf("spnego: sessions[%d]: %w", si, err)
		}
	}
	sup := sess.SupportedMech
	if sup == "" {
		sup = cfg.SupportedMech
	}
	if sup != "" {
		if _, err := resolveOID(sup); err != nil {
			return fmt.Errorf("spnego: sessions[%d]: %w", si, err)
		}
		if !containsOID(mechs, sup) {
			return fmt.Errorf("spnego: sessions[%d].supported_mech %q is not in the session offered mech_types (selection)", si, sup)
		}
	}
	state := "initial" // initial → init → resp/targ → (mic) → terminal
	for ei := range sess.Events {
		ev := &sess.Events[ei]
		kind := ev.Kind
		if !kindAllowed(profile, kind) {
			return fmt.Errorf("spnego: sessions[%d].events[%d] kind %q is not a %s carrier event (profile)", si, ei, kind, profile)
		}
		if kind == "targ" && negotiation != "init_targ" {
			return fmt.Errorf("spnego: sessions[%d].events[%d] kind %q requires negotiation %q — legacy targ must be explicitly declared (sequence)", si, ei, kind, "init_targ")
		}
		next, err := advance(state, kind, negotiation)
		if err != nil {
			return fmt.Errorf("spnego: sessions[%d].events[%d] kind %q: %v (sequence)", si, ei, kind, err)
		}
		state = next
		if ev.NegResult != nil {
			hi := 3
			if kind == "targ" {
				hi = 2
			}
			if *ev.NegResult < 0 || *ev.NegResult > hi {
				return fmt.Errorf("spnego: sessions[%d].events[%d].neg_result %d out of range 0..%d (neg_result)", si, ei, *ev.NegResult, hi)
			}
		}
	}
	if sess.NegResult != nil {
		hi := 3
		if negotiation == "init_targ" {
			hi = 2
		}
		if *sess.NegResult < 0 || *sess.NegResult > hi {
			return fmt.Errorf("spnego: sessions[%d].neg_result %d out of range 0..%d (neg_result)", si, *sess.NegResult, hi)
		}
	}
	return nil
}

// kindAllowed 判 kind 是否属该 profile 的载体事件集（profile↔载体一致性）。
func kindAllowed(profile, kind string) bool {
	if profile == "tcp" {
		switch kind {
		case "init", "resp", "targ", "mic":
			return true
		}
		return false
	}
	switch kind {
	case "init", "resp", "targ", "mic", "challenge", "http_success":
		return true
	}
	return false
}

// advance 推进会话状态机（契约 §5 事务序 t1→t2→(t3)：init → resp/targ →
// 可选 mic 续 → 终态；challenge/http_success 仅 http profile 的载体事件，
// init 前（探测 401）或 resp 后（终态 200）合法）。
func advance(state, kind, negotiation string) (string, error) {
	switch kind {
	case "challenge":
		if state == "initial" {
			return "challenged", nil
		}
		return state, fmt.Errorf("challenge after %s", state)
	case "init":
		if state == "initial" || state == "challenged" || state == "init" {
			return "init", nil
		}
		return state, fmt.Errorf("INIT after %s", state)
	case "resp", "targ":
		if kind == "resp" && negotiation == "init_targ" {
			return state, fmt.Errorf("resp in init_targ negotiation — use targ (sequence)")
		}
		if state == "init" || state == "mic" {
			return "responded", nil
		}
		return state, fmt.Errorf("%s before INIT (state %s)", strings.ToUpper(kind), state)
	case "mic":
		if state == "responded" {
			return "mic", nil
		}
		return state, fmt.Errorf("MIC before response (state %s)", state)
	case "http_success":
		if state == "responded" || state == "mic" || state == "terminal" {
			return "terminal", nil
		}
		return state, fmt.Errorf("carrier terminal status before response (state %s)", state)
	}
	return state, fmt.Errorf("unknown kind")
}

// validateWireFault rejects the 6 sanctioned injection values with their
// 主锚词（error_contains 断言；DescribeSPNEGOWireFault 单权威）。
func validateWireFault(kind string) error {
	anchor, err := core.DescribeSPNEGOWireFault(kind)
	if err != nil {
		return err
	}
	return fmt.Errorf("spnego: wire fault %s: negative-path injection rejected (anchor %s)", kind, anchor)
}
