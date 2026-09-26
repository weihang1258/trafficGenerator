// Package spnego — SPNEGO（RFC 4178）终结层生成器（D-SPNEGO-1 #47）。
//
// 链形（裁定1）：P-TCP `[ip,tcp,spnego]`（裸 TCP profile：整 DER 直发）；
// P-HTTP `[ip,tcp,http,spnego]`（http 作可选底座，透传变换器原样转发——
// 两 profile 均由本层自封帧，`OptionalOn ["http"]` 只是允许显式声明底座；
// ntlm 同构）。
//
// wire shape（裁定2/§10.7 M-shape-1 实测锚）：`0x60 { OID(S),
// A0 { 30 { A0{30{OIDs}}, A1{03 02 00 C0}, A2{04 token} } } }`——[n] 显式
// 包装 + 内层 universal tag 原样（M-shape-2 反证：多套 SEQUENCE 即
// Malformed）。negTokenResp/targ 的裸 `[1]` 选择枝统一包显式 SEQUENCE
// （negTokenResp 线形见 builder 注释；ntlm wrapSPNEGO 同口径）。
//
// 内层机制 token 一律 opaque（裁定5）：确定性 fixture 字节，只断言长度/
// 边界，不伪造密码学值（ntlm fixtureFill 同款口径）。
package spnego

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// fixture 缺省（契约 §2/§3 形态；最小可辨识档）。
const (
	// fixtureTokenLen 是 opaque token 缺省长度（32B：M-shape-1 实测锚
	// deadbeef(4B) 的规模化档；§10.3 DER 长形 268B 档由 #10 200B 显式覆盖）。
	fixtureTokenLen = 32
	// fixtureMICLen 是 RFC 形 mechListMIC 缺省长度（16B：MIC opaque 档）。
	fixtureMICLen = 16
	// fixtureHintName/HintAddress 是 negHints dissector 形缺省值（M-shape-3
	// 实测干净解出 hintName/hintAddress 的 fixture 档）。
	fixtureHintName    = "hint.example"
	fixtureHintAddress = "C0000201"
	// fixtureSrcPortHTTP 是 HTTP profile fixture 源端口（契约 §11.1：裸 TCP
	// 45061 / HTTP 45062 两档）。
	fixtureHost = "198.51.100.61"
)

// ---- 三结构 builder（D-SPNEGO-1 §12 DER 逐结构权威表）----

// buildInitialContextToken 产 GSS-API InitialContextToken：
// `0x60 { 06 06 2B 06 01 05 05 02, <negotiationToken> }`
// （RFC 2743 §3.1 语法权威；dissector spnego.thisMech/
// innerContextToken_element 实证）。
//
// 注意 negotiationToken 的 CHOICE tag 即线首那个 `[0]`/`[1]`——§12 DER 表把
// `innerContextToken [0] EXPLICIT` 与 CHOICE `negTokenInit [0]` 分开写，直译会
// 多套一层 A0；§10.7 M-shape-1 实测锚（`602906062b0601050502a01f301d…`，干净
// 解出）只有一个 A0，故 builder 以实测锚为准（§12 明示 M-shape-1 是 builder
// 硬约束）。
func buildInitialContextToken(negotiationToken []byte) []byte {
	inner := append(append([]byte{}, oidDER["1.3.6.1.5.5.2"]...), negotiationToken...)
	return tlv(0x60, inner)
}

// buildNegTokenInit 产 choice=`0xA0` 的 NegTokenInit：
// `A0 { 30 { A0{30{OIDs}}, A1{03 ..}, A2{04 token}, [A3 MIC | A3 Hints] } }`
// （RFC 4178 §4.2.1 + Appendix A——mechTypes [0]/reqFlags [1]/mechToken
// [2]/mechListMIC [3]；`[3]` 槽二义由 caller 经 micOrHints 互斥供给）。
func buildNegTokenInit(mechTypes []string, reqFlags *uint32, mechToken []byte, slot3 []byte) ([]byte, error) {
	if len(mechTypes) == 0 {
		return nil, fmt.Errorf("spnego: negTokenInit requires at least one mechType (oid)")
	}
	var oids []byte
	for _, m := range mechTypes {
		der, err := resolveOID(m)
		if err != nil {
			return nil, err
		}
		oids = append(oids, der...)
	}
	body := tlv(0xA0, tlv(0x30, oids)) // [0] MechTypeList（只包一层——§9 勘误⑨：A0{30{A0…}} 多套即 malformed）
	if reqFlags != nil {
		body = append(body, tlv(0xA1, tlv(0x03, contextFlagsContent(*reqFlags)))...) // [1] ContextFlags（M-shape-1 锚 `A1{03 02 00 C0}`）
	}
	if mechToken != nil {
		body = append(body, tlv(0xA2, octetString(mechToken))...) // [2] OCTET STRING
	}
	if slot3 != nil {
		body = append(body, slot3...) // [3]：MIC（RFC 形）或 negHints（dissector 形），caller 互斥
	}
	return tlv(0xA0, tlv(0x30, body)), nil
}

// wrapChoiceInit 包 InitialContextToken 外层（init/mic 事件的完整上线字节）。
func wrapChoiceInit(inner []byte) []byte { return buildInitialContextToken(inner) }

// buildNegTokenResp 产选择枝=`0xA1` 的 NegTokenResp（含显式 SEQUENCE 内层；
// RFC 4178 §4.2.2：negState [0]/supportedMech [1]/responseToken [2]/
// mechListMIC [3]；tshark `[1]` 枝统一读 negTokenTarg 模板——字段面
// negResult/supportedMech/responseToken 实测填充，裁定2 A 由通道分流吸收）。
func buildNegTokenResp(negResult int, supportedMech string, responseToken []byte, mic []byte) ([]byte, error) {
	if negResult < 0 || negResult > 3 {
		return nil, fmt.Errorf("spnego: negResult %d out of range 0..3 (RFC 4178 §4.2.2) (neg_result)", negResult)
	}
	body := tlv(0xA0, enumerated(negResult)) // [0] negState ENUMERATED
	if supportedMech != "" {
		der, err := resolveOID(supportedMech)
		if err != nil {
			return nil, err
		}
		body = append(body, tlv(0xA1, der)...) // [1] supportedMech
	}
	if responseToken != nil {
		body = append(body, tlv(0xA2, octetString(responseToken))...) // [2] OCTET STRING
	}
	if mic != nil {
		body = append(body, tlv(0xA3, octetString(mic))...) // [3] mechListMIC（RFC 形）
	}
	return tlv(0xA1, tlv(0x30, body)), nil
}

// buildNegTokenTarg 产旧式 negTokenTarg（RFC 2478 §3.2.1：negResult [0]
// （三值）/supportedMech [1]/responseToken [2]/mechListMIC [3]——§10.3 H1
// 勘误后与 NegTokenResp 同构；profile 必须显式声明 init_targ）。
func buildNegTokenTarg(negResult int, supportedMech string, responseToken []byte, mic []byte) ([]byte, error) {
	if negResult < 0 || negResult > 2 {
		return nil, fmt.Errorf("spnego: targ negResult %d out of range 0..2 (RFC 2478 §3.2.1, no request-mic) (neg_result)", negResult)
	}
	return buildNegTokenResp(negResult, supportedMech, responseToken, mic)
}

// buildNegHints 产 negHints（RFC 4178 §4.2.1 NegTokenInit OCTET STRING [3]
// 槽——dissector 把该槽读作 negHints/negHints_element（M-shape-3 实测干净
// 解出 hintName/hintAddress）：`A3 { 30 { A0{1B hintName}, A1{04
// hintAddress} } }`（两长度独立计算）。同槽的 RFC 形 mechListMIC 由 caller
// 互斥（裁定2 ②）。
func buildNegHints(name, addrHex string) ([]byte, error) {
	if name == "" {
		name = fixtureHintName
	}
	raw, err := hexBytes(addrHex, "neg_hints.hint_address")
	if err != nil {
		if strings.TrimSpace(addrHex) == "" {
			raw, _ = hexBytes(fixtureHintAddress, "neg_hints.hint_address")
		} else {
			return nil, err
		}
	}
	seq := append(tlv(0xA0, generalString(name)), tlv(0xA1, octetString(raw))...)
	return tlv(0xA3, tlv(0x30, seq)), nil
}

// ---- opaque 负载解析（Len 指针三态）----

// tokenBytes 求 token 外壳的线上字节：nil 块 = 缺省 fixture；Len 缺席 =
// fixtureTokenLen；显式 n = n 字节（含 0=零长占位，#9 两类面）。
func tokenBytes(t *core.SPNEGOToken, defLen int) []byte {
	if t == nil {
		return fixtureOpaque(defLen)
	}
	if t.Len != nil {
		if *t.Len <= 0 {
			return []byte{}
		}
		return fixtureOpaque(*t.Len)
	}
	return fixtureOpaque(defLen)
}

// micBytes 求 MIC 线上字节：nil 块 = 缺省 fixtureMICLen；Layout 非空非 rfc4178
// 由 planner 拒（此处只管字节）。
func micBytes(m *core.SPNEGOMIC) []byte {
	if m == nil {
		return fixtureOpaque(fixtureMICLen)
	}
	if m.Len != nil {
		if *m.Len <= 0 {
			return []byte{}
		}
		return fixtureOpaque(*m.Len)
	}
	return fixtureOpaque(fixtureMICLen)
}

// ---- 双 profile 成帧 ----

// frameTCP 渲染裸 TCP 事件：整 DER 直发（无私有长度前缀——契约 §2/§5.7；
// 接收端按 DER 父长度重组，segment 边界≠token 边界）。
func frameTCP(der []byte) []byte { return der }

// frameHTTP 渲染 HTTP/1.1 载体消息（RFC 4559 §4.2）：
//   - challenge（down）：401 + 裸 `WWW-Authenticate: Negotiate`（探测轮）；
//   - init/mic（up）：`Authorization: Negotiate <b64>`（b64=DER 传输包装）；
//   - resp/targ（down）：`WWW-Authenticate: Negotiate <b64>`；
//   - http_success（down）：200 OK（RFC 4559 §4.2 结果显式配置面）。
func frameHTTP(kind string, der []byte, host string) ([]byte, error) {
	switch kind {
	case "init", "mic":
		var b strings.Builder
		b.WriteString("GET / HTTP/1.1\r\n")
		b.WriteString("Host: " + host + "\r\n")
		b.WriteString("User-Agent: trafficgen-spnego\r\n")
		b.WriteString("Connection: keep-alive\r\n")
		b.WriteString("Authorization: Negotiate " + base64.StdEncoding.EncodeToString(der) + "\r\n\r\n")
		return []byte(b.String()), nil
	case "resp", "targ":
		var b strings.Builder
		b.WriteString("HTTP/1.1 401 Unauthorized\r\n")
		b.WriteString("WWW-Authenticate: Negotiate " + base64.StdEncoding.EncodeToString(der) + "\r\n")
		b.WriteString("Content-Length: 0\r\n")
		b.WriteString("Connection: keep-alive\r\n\r\n")
		return []byte(b.String()), nil
	case "challenge":
		return []byte("HTTP/1.1 401 Unauthorized\r\n" +
			"WWW-Authenticate: Negotiate\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: keep-alive\r\n\r\n"), nil
	case "http_success":
		return []byte("HTTP/1.1 200 OK\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: keep-alive\r\n\r\n"), nil
	default:
		return nil, fmt.Errorf("spnego: event kind %q is not an http carrier event (profile)", kind)
	}
}

// ---- 事件渲染（双 profile 入口）----

type frame struct {
	up    bool
	bytes []byte
}

// renderEvent 渲染一事件：DER 消息（按 kind）→ 按 profile 成帧。
func renderEvent(kind string, sess *core.SPNEGOSession, cfg *core.SPNEGOConfig, host string) (frame, error) {
	profile := profileOf(cfg)
	var der []byte
	var err error
	up := false
	switch kind {
	case "init":
		up = true
		der, err = renderInit(sess, cfg)
	case "resp":
		der, err = renderResp(sess, cfg)
	case "targ":
		der, err = renderTarg(sess, cfg)
	case "mic":
		up = true
		der, err = renderMIC(sess, cfg)
	case "challenge", "http_success":
		// 纯载体事件（无 DER；仅 http profile）。
	default:
		return frame{}, fmt.Errorf("spnego: unknown event kind %q (kind)", kind)
	}
	if err != nil {
		return frame{}, err
	}
	var wire []byte
	switch profile {
	case "tcp":
		if kind == "challenge" || kind == "http_success" {
			return frame{}, fmt.Errorf("spnego: event kind %q is an http carrier event, not a tcp carrier event (profile)", kind)
		}
		wire = frameTCP(der)
	case "http":
		wire, err = frameHTTP(kind, der, host)
		if err != nil {
			return frame{}, err
		}
	default:
		return frame{}, fmt.Errorf("spnego: unknown profile %q (profile)", profile)
	}
	return frame{up: up, bytes: wire}, nil
}

// profileOf 归一 profile（空 = 缺省档 tcp；契约 §2）。
func profileOf(cfg *core.SPNEGOConfig) string {
	if cfg == nil || cfg.Profile == "" {
		return "tcp"
	}
	return strings.ToLower(strings.TrimSpace(cfg.Profile))
}

// sessionMechs 求会话实际候选列表（会话覆盖 > 配置级 > 缺省单 Kerberos）。
func sessionMechs(sess *core.SPNEGOSession, cfg *core.SPNEGOConfig) []string {
	if sess != nil && len(sess.MechTypes) > 0 {
		return sess.MechTypes
	}
	if cfg != nil && len(cfg.MechTypes) > 0 {
		return cfg.MechTypes
	}
	return []string{"1.2.840.113554.1.2.2"}
}

// sessionSupported 求会话实际选定 OID（会话覆盖 > 配置级 > 列表首项）。
func sessionSupported(sess *core.SPNEGOSession, cfg *core.SPNEGOConfig) string {
	if sess != nil && sess.SupportedMech != "" {
		return sess.SupportedMech
	}
	if cfg != nil && cfg.SupportedMech != "" {
		return cfg.SupportedMech
	}
	return sessionMechs(sess, cfg)[0]
}

// sessionNegResult 求会话实际协商进展（事件覆盖 > 会话覆盖 > 配置级 > 缺省）。
func sessionNegResult(ev *core.SPNEGOEvent, sess *core.SPNEGOSession, cfg *core.SPNEGOConfig, def int) int {
	if ev != nil && ev.NegResult != nil {
		return *ev.NegResult
	}
	if sess != nil && sess.NegResult != nil {
		return *sess.NegResult
	}
	if cfg != nil && cfg.NegResult != nil {
		return *cfg.NegResult
	}
	return def
}

// slot3 求 NegTokenInit [3] 槽字节：dissector 形 negHints 与 RFC 形 MIC
// 互斥（裁定2 ②——同消息同时声明由 planner 拒，此处按 hints 优先）。
func slot3(cfg *core.SPNEGOConfig) ([]byte, error) {
	if cfg != nil && cfg.NegHints != nil && strings.EqualFold(strings.TrimSpace(cfg.NegHints.Carry), "dissector") {
		return buildNegHints(cfg.NegHints.HintName, cfg.NegHints.HintAddress)
	}
	if cfg != nil && cfg.MechListMIC != nil {
		return tlv(0xA3, octetString(micBytes(cfg.MechListMIC))), nil
	}
	return nil, nil
}

// reqFlagsOrNil 归一 reqFlags：schema 缺省 0 经严格解码后恒为"显式 0"指针，
// 但契约 §3/§12 明示 reqFlags OPTIONAL 且 RFC 4178 §4.2.1 "initiator SHOULD
// omit"——0 值不发射该字段（#5 显式 0xC0 才发射）。
func reqFlagsOrNil(cfg *core.SPNEGOConfig) *uint32 {
	if cfg == nil || cfg.ReqFlags == nil || *cfg.ReqFlags == 0 {
		return nil
	}
	return cfg.ReqFlags
}

// renderInit 渲染 negTokenInit（up，InitialContextToken 外层）。
func renderInit(sess *core.SPNEGOSession, cfg *core.SPNEGOConfig) ([]byte, error) {
	s3, err := slot3(cfg)
	if err != nil {
		return nil, err
	}
	var mt *core.SPNEGOToken
	if cfg != nil {
		mt = cfg.MechToken
	}
	init, err := buildNegTokenInit(sessionMechs(sess, cfg), reqFlagsOrNil(cfg), tokenBytes(mt, fixtureTokenLen), s3)
	if err != nil {
		return nil, err
	}
	return wrapChoiceInit(init), nil
}

// renderResp 渲染 negTokenResp（down，无 InitialContextToken 外层——
// resp 是 acceptor 直接回的选择枝消息）。
func renderResp(sess *core.SPNEGOSession, cfg *core.SPNEGOConfig) ([]byte, error) {
	var rt *core.SPNEGOToken
	if cfg != nil {
		rt = cfg.ResponseToken
	}
	var mic []byte
	if cfg != nil && cfg.MechListMIC != nil {
		mic = micBytes(cfg.MechListMIC)
	}
	return buildNegTokenResp(sessionNegResult(nil, sess, cfg, 0), sessionSupported(sess, cfg), tokenBytes(rt, fixtureTokenLen), mic)
}

// renderTarg 渲染旧式 negTokenTarg（down；RFC 2478 §3.2.1 三值）。
func renderTarg(sess *core.SPNEGOSession, cfg *core.SPNEGOConfig) ([]byte, error) {
	var rt *core.SPNEGOToken
	if cfg != nil {
		rt = cfg.ResponseToken
	}
	var mic []byte
	if cfg != nil && cfg.MechListMIC != nil {
		mic = micBytes(cfg.MechListMIC)
	}
	return buildNegTokenTarg(sessionNegResult(nil, sess, cfg, 0), sessionSupported(sess, cfg), tokenBytes(rt, fixtureTokenLen), mic)
}

// renderMIC 渲染补 MIC 的 negTokenInit（up；t3 MIC 续——request_mic(3) 后
// initiator 补 mechListMIC，验证输入=原始 DER mechTypes，RFC 4178 §5）。
func renderMIC(sess *core.SPNEGOSession, cfg *core.SPNEGOConfig) ([]byte, error) {
	var mt *core.SPNEGOToken
	if cfg != nil {
		mt = cfg.MechToken
	}
	micCfg := &core.SPNEGOMIC{}
	if cfg != nil && cfg.MechListMIC != nil {
		micCfg = cfg.MechListMIC
	}
	s3 := tlv(0xA3, octetString(micBytes(micCfg)))
	init, err := buildNegTokenInit(sessionMechs(sess, cfg), reqFlagsOrNil(cfg), tokenBytes(mt, fixtureTokenLen), s3)
	if err != nil {
		return nil, err
	}
	return wrapChoiceInit(init), nil
}

// ---- walker（会话状态单权威：walk renderEvent 同路径）----

type spnegoWalker struct {
	cfg     *core.SPNEGOConfig
	srcPort uint16
	dstPort uint16
	host    string
}

func newWalker(cfg *core.SPNEGOConfig, srcPort, dstPort uint16, host string) *spnegoWalker {
	return &spnegoWalker{cfg: cfg, srcPort: srcPort, dstPort: dstPort, host: host}
}

// resolveEvent 求事件实际方向（缺省按 kind 派生：init/mic=up）。
func (w *spnegoWalker) resolveEvent(ev *core.SPNEGOEvent, kind string) bool {
	defUp := kind == "init" || kind == "mic"
	if ev.Up == nil {
		return defUp
	}
	return *ev.Up
}

// ---- Generate（链驱动入口，dcerpc/dtls/kerberos/ntlm 同族）----

// SPNEGOGenerator is the terminal-layer generator for spnego chains.
type SPNEGOGenerator struct{}

func (g *SPNEGOGenerator) Name() string { return "spnego" }

// GenEvents/EmitEvent mark the event-generator face（kerberos/bacnet 同款）。
func (g *SPNEGOGenerator) GenEvents() layers.EventGenerator { return g }
func (g *SPNEGOGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("spnego generator: EmitEvent is not wired")
}

// Generate 逐会话逐事件渲染（链驱动入口）。
func (g *SPNEGOGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("spnego generator: request is nil")
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("spnego generator: EmitMsg is nil")
	}
	cfg := req.Meta.SPNEGO
	if cfg == nil {
		cfg = &core.SPNEGOConfig{}
	}
	if err := (&Planner{}).Validate(core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		SPNEGO:  cfg,
	}); err != nil {
		return err
	}

	host := req.Meta.DstIP
	if host == "" {
		host = fixtureHost
	}
	w := newWalker(cfg, req.Meta.SrcPort, req.Meta.DstPort, host)

	// 空配置缺省基线（bacnet/dtls/kerberos/ntlm 家族同款）：无 sessions 发
	// 一条最小 init（tcp 缺省档），避免裸 {"spnego":{}} 链静默 0 包。
	if len(cfg.Sessions) == 0 {
		sess := &core.SPNEGOSession{}
		ev := &core.SPNEGOEvent{Kind: "init"}
		fr, err := w.renderSessionEvent(sess, ev, 0, 0)
		if err != nil {
			return err
		}
		return req.EmitMsg(layers.MessageEvent{Up: fr.up, Bytes: fr.bytes})
	}

	for si := range cfg.Sessions {
		sess := &cfg.Sessions[si]
		for ei := range sess.Events {
			ev := &sess.Events[ei]
			fr, err := w.renderSessionEvent(sess, ev, si, ei)
			if err != nil {
				return fmt.Errorf("spnego: sessions[%d].events[%d]: %w", si, ei, err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err := req.EmitMsg(layers.MessageEvent{Up: fr.up, Bytes: fr.bytes}); err != nil {
				return err
			}
		}
	}
	return nil
}

// renderSessionEvent 渲染一个会话事件（walker 单权威：Validate 与 Generate
// 走同一路径——校验即生成前置演练，不做第二套规则；ntlm 同款）。
func (w *spnegoWalker) renderSessionEvent(sess *core.SPNEGOSession, ev *core.SPNEGOEvent, si, ei int) (frame, error) {
	kind := ev.Kind
	fr, err := renderEvent(kind, sess, w.cfg, w.host)
	if err != nil {
		return frame{}, err
	}
	fr.up = w.resolveEvent(ev, kind)
	return fr, nil
}

// init registers the generator + validator（bacnet/kerberos/ntlm 同款接线）。
func init() {
	layers.RegisterLayerGenerator("spnego", func() (layers.LayerGenerator, error) { return &SPNEGOGenerator{}, nil })
	layers.RegisterLayerValidator("spnego", func(spec *core.FlowSpec) error { return (&Planner{}).Validate(*spec) })
}
