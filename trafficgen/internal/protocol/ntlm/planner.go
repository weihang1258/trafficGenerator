// Package ntlm planner：负例校验（6 wire_fault 一行一注入——设计 §2/§10 与
// 用例 §4 三方同序）+ 结构/状态守卫（SecurityBuffer 边界、UTF-16 偶数长度、
// flags↔TargetInfo 一致、AV_PAIR EOL、载体↔profile 一致、会话事件顺序）。
// 每个被拒 spec 必须传播为 task error——绝不产出 completed/0-packet 假成功。
//
// 处置表：6 负例三通道——4 走 validateWireFault 注入拒（message_length/
// security_buffer/offset_overflow/flags_target_info：生成路径结构上恒自洽，
// 注入是唯一通道）；1 走自然非法配置（blob_av_pairs：缺 EOL/AV 值非法经守卫
// 拒）；1 走 validate_layers 预检 + 生成器 profile 守卫（carrier_profile：
// 缺 tcp 载体/链夹 udp/profile↔事件 kind 混用）。
package ntlm

import (
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner is the layer-validator entry type (kerberos/dtls 同款).
type Planner struct{}

// Validate checks an ntlm flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error { return validateSpec(spec) }

// validateSpec: cfg == nil（bare {"ntlm":{}} 层或缺键）通过：生成器发一条
// 最小 NEGOTIATE 基线（缺省档 smb2——bacnet/dtls/kerberos 空配置缺省家族
// 同款，裸层不静默 0 包）。
func validateSpec(spec core.FlowSpec) error {
	cfg := spec.NTLM
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	if err := validateProfile(cfg); err != nil {
		return err
	}
	flags := resolveFlags(cfg.Flags)
	if err := validateFlags(cfg, flags); err != nil {
		return err
	}
	for si := range cfg.Sessions {
		if err := validateSession(cfg, &cfg.Sessions[si], si); err != nil {
			return err
		}
	}
	return nil
}

// validateProfile 拒未知 profile / version / outer（契约 §2 键表：profile 必填
// 语义、不能混用；空 profile = 缺省档 smb2）。
func validateProfile(cfg *core.NTLMConfig) error {
	switch profileOf(cfg) {
	case "smb2", "http-negotiate":
	default:
		return fmt.Errorf("ntlm: unknown profile %q — must be smb2 or http-negotiate (profile)", cfg.Profile)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Version)) {
	case "", "ntlmv2":
	default:
		return fmt.Errorf("ntlm: version %q is not supported — this contract covers NTLMv2 only (NTLMv1/LM dialect is out of scope) (version)", cfg.Version)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Outer)) {
	case "", "none", "spnego":
	default:
		return fmt.Errorf("ntlm: unknown outer %q — must be none or spnego (spnego)", cfg.Outer)
	}
	if cfg.MIC != nil && *cfg.MIC {
		// 无授权密钥不生成 MIC 值：只允许声明出现（长度/边界面），值不伪造。
		// （声明出现是合法 fixture；此处不拒，仅作语义记录。）
	}
	if cfg.Type3 != nil {
		if err := validateType3Config(cfg.Type3); err != nil {
			return err
		}
	}
	if cfg.TargetInfo != nil {
		if err := validateTargetInfoConfig(cfg.TargetInfo); err != nil {
			return err
		}
	}
	return nil
}

// validateTargetInfoConfig 守 Type 2 TargetInfo 的 AV_PAIR 序列面（契约 §6：
// 序列必须以 MsvAvEOL 收尾；扩展项 Text/ValueHex 互斥且 hex 合法）。
func validateTargetInfoConfig(ti *core.NTLMTargetInfo) error {
	if ti.NoEOL {
		return fmt.Errorf("ntlm: target_info.no_eol declares an AV_PAIR sequence without MsvAvEOL terminator (av)")
	}
	for _, p := range ti.Extra {
		if err := validateAVPair(p); err != nil {
			return err
		}
	}
	if ti.Timestamp != "" && !strings.EqualFold(strings.TrimSpace(ti.Timestamp), "auto") {
		raw, err := hexBytes(ti.Timestamp, "target_info.timestamp")
		if err != nil {
			return err
		}
		if len(raw) != 8 {
			return fmt.Errorf("ntlm: target_info.timestamp hex %q is %d bytes, want 8 (length)", ti.Timestamp, len(raw))
		}
	}
	return nil
}

// validateType3Config 守 NTLMv2 blob/response 的长度面（契约 §5/§7）。
func validateType3Config(t3 *core.NTLMType3Config) error {
	if t3.LMResponseLen < 0 {
		return fmt.Errorf("ntlm: ntlmv2_response.lm_response_len %d is negative (length)", t3.LMResponseLen)
	}
	if t3.LMResponseLen > 0xFF {
		// security buffer 长度字段 16-bit；LM response 是短 proof 面，
		// 超过 255 即非法配置（§5 规则 1：Len 与承载一致）。
		return fmt.Errorf("ntlm: ntlmv2_response.lm_response_len %d exceeds the LM response bound (255) (length)", t3.LMResponseLen)
	}
	if t3.MaxLenPad < 0 {
		return fmt.Errorf("ntlm: ntlmv2_response.max_len_pad %d is negative (length)", t3.MaxLenPad)
	}
	if t3.NoEOL {
		return fmt.Errorf("ntlm: ntlmv2_response.no_eol declares an AV_PAIR sequence without MsvAvEOL terminator (av)")
	}
	for _, p := range t3.AVPairs {
		if err := validateAVPair(p); err != nil {
			return err
		}
	}
	if t3.Timestamp != "" && !strings.EqualFold(strings.TrimSpace(t3.Timestamp), "auto") {
		raw, err := hexBytes(t3.Timestamp, "ntlmv2_response.timestamp")
		if err != nil {
			return err
		}
		if len(raw) != 8 {
			return fmt.Errorf("ntlm: ntlmv2_response.timestamp hex %q is %d bytes, want 8 (length)", t3.Timestamp, len(raw))
		}
	}
	if t3.ClientChallenge != "" && !strings.EqualFold(strings.TrimSpace(t3.ClientChallenge), "auto") {
		raw, err := hexBytes(t3.ClientChallenge, "ntlmv2_response.client_challenge")
		if err != nil {
			return err
		}
		if len(raw) != 8 {
			return fmt.Errorf("ntlm: ntlmv2_response.client_challenge hex %q is %d bytes, want 8 (length)", t3.ClientChallenge, len(raw))
		}
	}
	return nil
}

// validateAVPair 守单项 AV_PAIR（Text/ValueHex 互斥；文本编码面）。
func validateAVPair(p core.NTLMAVPair) error {
	if p.Text != "" && p.ValueHex != "" {
		return fmt.Errorf("ntlm: av pair id %d declares both text and value_hex (av)", p.ID)
	}
	if p.ValueHex != "" {
		if _, err := hexBytes(p.ValueHex, fmt.Sprintf("av pair id %d value_hex", p.ID)); err != nil {
			return err
		}
	}
	return nil
}

// validateFlags 守 flags↔TargetInfo 一致性 + OEM 编码面（契约 §6/§2）。
func validateFlags(cfg *core.NTLMConfig, flags uint32) error {
	ti := cfg.TargetInfo
	if flags&flagTargetInfo == 0 {
		// flags.TARGET_INFO 关闭却声明了 AV 面/Type 2 TargetName = 协商不一致。
		if ti != nil {
			return fmt.Errorf("ntlm: flags.target_info is off but target_info is declared — flags/TargetInfo negotiation is inconsistent (flags)")
		}
		for si := range cfg.Sessions {
			if cfg.Sessions[si].TargetName != "" {
				return fmt.Errorf("ntlm: flags.target_info is off but sessions[%d].target_name is declared (flags)", si)
			}
		}
	}
	if flags&flagUnicode == 0 {
		// Unicode 关闭 = OEM 编码：非 latin-1 字符无法编码（契约 §5 规则 3
		// 的编码面守卫）。
		texts := []string{}
		if ti != nil {
			texts = append(texts, ti.NbComputerName, ti.NbDomainName, ti.DnsComputerName,
				ti.DnsDomainName, ti.DnsTreeName, ti.TargetName)
			for _, ex := range ti.Extra {
				texts = append(texts, ex.Text)
			}
		}
		for si := range cfg.Sessions {
			s := &cfg.Sessions[si]
			texts = append(texts, s.Domain, s.User, s.Workstation, s.TargetName)
		}
		for _, t := range texts {
			for _, r := range t {
				if r > 0xFF {
					return fmt.Errorf("ntlm: unicode flag is off (OEM encoding) but text %q contains a non-latin-1 rune (unicode)", t)
				}
			}
		}
	}
	return nil
}

// validateSession 逐会话：事件 kind 合法（profile↔kind 一致）+ 状态机顺序 +
// 结构守卫（与 renderEvent 同一权威——校验即生成前置演练，不做第二套规则）。
func validateSession(cfg *core.NTLMConfig, sess *core.NTLMSession, si int) error {
	profile := profileOf(cfg)
	state := "initial" // initial → negotiate → challenge → authenticate → terminal
	for ei := range sess.Events {
		ev := &sess.Events[ei]
		kind := ev.Kind
		if !kindAllowed(profile, kind) {
			return fmt.Errorf("ntlm: sessions[%d].events[%d] kind %q is not a %s carrier event (profile)", si, ei, kind, profile)
		}
		next, err := advance(state, kind)
		if err != nil {
			return fmt.Errorf("ntlm: sessions[%d].events[%d] kind %q: %v (sequence)", si, ei, kind, err)
		}
		state = next
		if ev.SessionKeyLen != nil && (*ev.SessionKeyLen < 0 || *ev.SessionKeyLen > 0xFFFF) {
			return fmt.Errorf("ntlm: sessions[%d].events[%d].session_key_len %d out of range (length)", si, ei, *ev.SessionKeyLen)
		}
	}
	if cfg.SessionKeyLen < 0 || cfg.SessionKeyLen > 0xFFFF {
		return fmt.Errorf("ntlm: encrypted_random_session_key length %d out of range (length)", cfg.SessionKeyLen)
	}
	// ServerChallenge fixture 钉值面：必须 16-hex。
	if !strings.EqualFold(strings.TrimSpace(sess.ServerChallenge), "auto") && strings.TrimSpace(sess.ServerChallenge) != "" {
		raw, err := hexBytes(sess.ServerChallenge, "server_challenge")
		if err != nil {
			return err
		}
		if len(raw) != 8 {
			return fmt.Errorf("ntlm: sessions[%d].server_challenge hex %q is %d bytes, want 8 (length)", si, sess.ServerChallenge, len(raw))
		}
	}
	return nil
}

// kindAllowed 判 kind 是否属该 profile 的载体事件集（profile↔载体一致性）。
func kindAllowed(profile, kind string) bool {
	if profile == "smb2" {
		switch kind {
		case "negotiate", "challenge", "authenticate", "session_setup_success", "session_setup_failure":
			return true
		}
		return false
	}
	switch kind {
	case "negotiate", "challenge", "authenticate", "challenge_401", "http_success", "http_unauthorized":
		return true
	}
	return false
}

// advance 推进会话状态机（契约 §9）：Initial → NegotiateSent → ChallengeReceived
// → AuthenticateSent → Accepted/Rejected；重试允许重发同一 negotiate/challenge
// （§9 重试语义），但不得跳级或倒序。
func advance(state, kind string) (string, error) {
	switch kind {
	case "negotiate":
		if state == "initial" || state == "negotiate" {
			return "negotiate", nil
		}
		return state, fmt.Errorf("NEGOTIATE after %s", state)
	case "challenge", "challenge_401":
		// 重试语义（契约 §9）：服务器可在 AUTHENTICATE 后再发 challenge
		// （3 轮形态：Type 3 后仍 MORE_PROCESSING_REQUIRED——§14.2 矩阵
		// #12 行），故 challenge 在 negotiate/challenge/authenticate 三态
		// 均合法；Initial 态仍拒（不得跳级）。
		if state == "negotiate" || state == "challenge" || state == "authenticate" {
			return "challenge", nil
		}
		return state, fmt.Errorf("CHALLENGE before NEGOTIATE (state %s)", state)
	case "authenticate":
		if state == "challenge" || state == "authenticate" {
			return "authenticate", nil
		}
		return state, fmt.Errorf("AUTHENTICATE before CHALLENGE (state %s)", state)
	case "session_setup_success", "session_setup_failure", "http_success", "http_unauthorized":
		if state == "authenticate" || state == "terminal" {
			return "terminal", nil
		}
		return state, fmt.Errorf("carrier terminal status before AUTHENTICATE (state %s)", state)
	}
	return state, fmt.Errorf("unknown kind")
}

// validateWireFault rejects the 6 sanctioned injection values with their
// 主锚词（error_contains 断言；DescribeNTLMWireFault 单权威）。
func validateWireFault(kind string) error {
	anchor, err := core.DescribeNTLMWireFault(kind)
	if err != nil {
		return err
	}
	return fmt.Errorf("ntlm: wire fault %s: negative-path injection rejected (anchor %s)", kind, anchor)
}
