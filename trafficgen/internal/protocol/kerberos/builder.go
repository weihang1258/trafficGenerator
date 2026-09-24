// Package kerberos — Kerberos V5（RFC 4120）终结层。
//
// Register* functions run at init() time (in builder.go), wiring the
// kerberos layer into the chain planner and generator factory. The
// side-effect import _ "…/protocol/kerberos" activates this registration.
//
// Kerberos = [ip → udp|tcp → kerberos]（双载体族——裁定1；DependsOn ["udp"]
// 缺省 + TransportOn ["udp","tcp"]；FieldContract udp.dst_port=88——tshark
// kerberos 分解器自动解码依赖）。UDP 每事件一 datagram；TCP 每事件前置
// 4-byte BE record length（不含自身——RFC 4120 §6，裁定7）。
//
// 消息 = 六型 DER definite-length（P2 tag 权威表——RFC 4120 §5.2–5.4.2）。
// msg-type↔顶层 tag 一致性是实义校验（裁定6：负例 #17 通道）。加密边界
// opaque（裁定5——etype/kvno/cipher_len 结构化可见，密文确定性填充）。
package kerberos

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// kind→(application tag number, msg-type) 权威映射（RFC 4120 §5.1 表；
// 裁定6 一致性校验面——声明 msg_type 偏离即拒）。
var kindTable = map[string]struct {
	tag     byte
	msgType int
}{
	"as_req":    {10, 10},
	"as_rep":    {11, 11},
	"tgs_req":   {12, 12},
	"tgs_rep":   {13, 13},
	"ap_req":    {14, 14},
	"ap_rep":    {15, 15},
	"krb_error": {30, 30},
}

// fixture 缺省（契约 §2 形态；MIT kinit 惯用值）。
const (
	fixtureFill      = 0xA5 // cipher/padata-value 确定性填充（裁定5）
	fixtureCipherLen = 52   // EncryptedData cipher 缺省长度（aes256 外壳量级）
	fixtureNonce     = 778001
	fixtureTill      = "20370913024805Z"
	fixtureTime      = "20260924120000Z"
	fixtureNameType  = 1  // KRB5_NT_PRINCIPAL
	fixtureEType     = 18 // aes256-cts-hmac-sha1-96（RFC 3962）
	defaultKDCPort   = 88
)

// ---- DER 结构组装（P2 tag 权威表逐行）----

// principalName renders PrincipalName ::= SEQUENCE{ name-type[0],
// name-string[1] SEQ OF KerberosString（GeneralString——P5 校准轮实修）}.
func principalName(nameType int, components []string) []byte {
	var strs [][]byte
	for _, c := range components {
		strs = append(strs, derGStr(c))
	}
	nameString := derSeq(strs...)
	return derSeq(derCtx(0, derInteger(nameType)), derCtx(1, nameString))
}

// encryptedData renders EncryptedData ::= SEQUENCE{ etype[0], kvno[1] OPTIONAL, cipher[2] }.
func encryptedData(e *core.KerberosEvent) []byte {
	etype := fixtureEType
	if e.EType != nil {
		etype = *e.EType
	}
	cipherLen := e.CipherLen
	if cipherLen <= 0 {
		cipherLen = fixtureCipherLen
	}
	cipher := make([]byte, cipherLen)
	for i := range cipher {
		cipher[i] = fixtureFill
	}
	parts := [][]byte{derCtx(0, derInteger(etype))}
	if e.KVNO != nil {
		parts = append(parts, derCtx(1, derInteger(*e.KVNO)))
	}
	parts = append(parts, derCtx(2, tlv(0x04, cipher))) // OCTET STRING primitive
	return derSeq(parts...)
}

// ticket renders Ticket ::= [APPLICATION 1] SEQUENCE{ tkt-vno[0]=5, realm[1], sname[2], enc-part[3] }.
func ticket(e *core.KerberosEvent) []byte {
	realm := e.Realm
	if realm == "" {
		realm = "EXAMPLE.TEST"
	}
	nameType := fixtureNameType
	if e.NameType != nil {
		nameType = *e.NameType
	}
	sname := e.SName
	if sname == nil {
		sname = []string{"krbtgt", realm}
	}
	body := derSeq(
		derCtx(0, derInteger(5)),
		derCtx(1, derGStr(realm)),
		derCtx(2, principalName(nameType, sname)),
		derCtx(3, encryptedData(e)),
	)
	return derApp(1, body)
}

// padataSeq renders METHOD-DATA ::= SEQUENCE OF PA-DATA（保序——RFC 6113）。
// 两个已知类型必须结构自洽（tshark 对 padata-value 递归解剖，raw 填充触发
// Malformed exception——P5 校准轮实修）：
//   - type 1 PA-TGS-REQ（RFC 4120 §7.5.1）：value = 完整 AP-REQ DER
//     （ticket/authenticator opaque——设计 §6"PA-TGS-REQ 的 AP-REQ 载体"）；
//   - type 2 PA-ENC-TIMESTAMP：value = EncryptedData{ etype, cipher=opaque
//     ValueLen 字节 }（RFC 4120 §5.4.1——timestamp 明文不可见，cipher 不透明，
//     裁定5）；
//   - type 128 PA-PAC-REQUEST（MS-KILE，非 PA-TGS-REQ——tshark 按 128 解剖
//     BOOLEAN）：value = [0] BOOLEAN TRUE（请求 PAC——P5 校准轮实修：128
//     当 TGS-REQ 载体是 RFC 误记）；
//   - 其余类型：raw 确定性填充（未知类型 tshark 不递归，不触发解剖）。
func padataSeq(pas []core.KerberosPAData, e *core.KerberosEvent) []byte {
	etype := fixtureEType
	if e.EType != nil {
		etype = *e.EType
	}
	var seqs [][]byte
	for _, pa := range pas {
		var val []byte
		switch pa.Type {
		case 1:
			// PA-TGS-REQ 携带 TGT：嵌入 AP-REQ 的 ticket 用 krbtgt 缺省
			// 主体（清空会话 SName/CName——目标 service 主体只在 req-body
			// sname 面，不进内嵌票据），etype/kvno/cipher_len 沿事件。
			tgt := *e
			tgt.SName, tgt.CName = nil, nil
			val = apReq(&tgt)
		case 2:
			cipher := make([]byte, pa.ValueLen)
			for i := range cipher {
				cipher[i] = fixtureFill
			}
			val = derSeq(derCtx(0, derInteger(etype)), derCtx(2, tlv(0x04, cipher)))
		case 128:
			val = tlv(0x01, []byte{0xFF})
		default:
			val = make([]byte, pa.ValueLen)
			for i := range val {
				val[i] = fixtureFill
			}
		}
		seqs = append(seqs, derSeq(
			derCtx(1, derInteger(pa.Type)),
			derCtx(2, tlv(0x04, val)),
		))
	}
	return derSeq(seqs...)
}

// kdcOptions renders the 5-byte all-zero BIT STRING（03 05 00 00000000）。
func kdcOptions() []byte { return derCtx(0, derBitString(make([]byte, 4))) }

// kdcReq renders KDC-REQ（AS-REQ [10]/TGS-REQ [12] 共用）：
// SEQUENCE{ pvno[1]=5, msg-type[2], padata[3] OPTIONAL, req-body[4] }；
// req-body = SEQUENCE{ kdc-options[0], cname[1] OPTIONAL, realm[2],
// sname[3] OPTIONAL, from[4] OPTIONAL, till[5], rtime[6] OPTIONAL,
// nonce[7], etype[8] SEQ{Int32}, addresses[9]/enc-authz-data[10]/
// additional-tickets[11] OPTIONAL 不渲染 }（RFC 4120 §5.4.1——P5 校准轮
// 实修：原 till[7]/nonce[9]/etype[10] 标签号错误）。
func kdcReq(tag byte, msgType int, e *core.KerberosEvent) ([]byte, error) {
	nonce := fixtureNonce
	if e.Nonce != nil {
		nonce = *e.Nonce
	}
	till := e.Till
	if till == "" {
		till = fixtureTill
	}
	etype := fixtureEType
	if e.EType != nil {
		etype = *e.EType
	}
	realm := e.Realm
	if realm == "" {
		realm = "EXAMPLE.TEST"
	}
	reqParts := [][]byte{kdcOptions()}
	if len(e.CName) > 0 {
		nameType := fixtureNameType
		if e.NameType != nil {
			nameType = *e.NameType
		}
		reqParts = append(reqParts, derCtx(1, principalName(nameType, e.CName)))
	}
	reqParts = append(reqParts, derCtx(2, derGStr(realm)))
	if len(e.SName) > 0 {
		nameType := fixtureNameType
		if e.NameType != nil {
			nameType = *e.NameType
		}
		reqParts = append(reqParts, derCtx(3, principalName(nameType, e.SName)))
	}
	reqParts = append(reqParts,
		derCtx(5, derGeneralizedTime(till)),
		derCtx(7, derInteger(nonce)),
		derCtx(8, derSeq(derInteger(etype))),
	)
	reqBody := derSeq(reqParts...)
	parts := [][]byte{
		derCtx(1, derInteger(5)), // pvno [1]（KDC-REQ 特有——REP 是 [0]）
		derCtx(2, derInteger(msgType)),
	}
	if len(e.PAData) > 0 {
		parts = append(parts, derCtx(3, padataSeq(e.PAData, e)))
	}
	parts = append(parts, derCtx(4, reqBody))
	return derApp(tag, derSeq(parts...)), nil
}

// kdcRep renders KDC-REP（AS-REP [11]/TGS-REP [13] 共用）：
// SEQUENCE{ pvno[0]=5, msg-type[1], crealm[3], cname[4], ticket[5], enc-part[6] }.
func kdcRep(tag byte, msgType int, e *core.KerberosEvent) []byte {
	realm := e.Realm
	if realm == "" {
		realm = "EXAMPLE.TEST"
	}
	crealm := e.CRealm
	if crealm == "" {
		crealm = realm
	}
	nameType := fixtureNameType
	if e.NameType != nil {
		nameType = *e.NameType
	}
	cname := e.CName
	if cname == nil {
		cname = []string{"user"}
	}
	return derApp(tag, derSeq(
		derCtx(0, derInteger(5)),
		derCtx(1, derInteger(msgType)),
		derCtx(3, derGStr(crealm)),
		derCtx(4, principalName(nameType, cname)),
		derCtx(5, ticket(e)),
		derCtx(6, encryptedData(e)),
	))
}

// apReq renders AP-REQ ::= SEQUENCE{ pvno[0]=5, msg-type[1]=14, ap-options[2], ticket[3], authenticator[4] }.
func apReq(e *core.KerberosEvent) []byte {
	return derApp(14, derSeq(
		derCtx(0, derInteger(5)),
		derCtx(1, derInteger(14)),
		derCtx(2, derBitString(make([]byte, 4))),
		derCtx(3, ticket(e)),
		derCtx(4, encryptedData(e)), // authenticator
	))
}

// apRep renders AP-REP ::= SEQUENCE{ pvno[0]=5, msg-type[1]=15, enc-part[2] }.
func apRep(e *core.KerberosEvent) []byte {
	return derApp(15, derSeq(
		derCtx(0, derInteger(5)),
		derCtx(1, derInteger(15)),
		derCtx(2, encryptedData(e)),
	))
}

// krbError renders KRB-ERROR ::= SEQUENCE{ pvno[0]=5, msg-type[1]=30,
// ctime[2]/cusec[3] OPTIONAL, stime[4], susec[5], error-code[6], crealm[7]
// OPTIONAL, cname[8] OPTIONAL, realm[9], sname[10] OPTIONAL, e-data[11]/
// e-text[12] OPTIONAL（e-text = KerberosString——P5 校准轮实修，原 [11]
// OCTET STRING 错标 e-data 槽）}.
func krbError(e *core.KerberosEvent) ([]byte, error) {
	if e.ErrorCode == nil {
		return nil, fmt.Errorf("kerberos: krb_error event requires error_code (kind)")
	}
	stime := e.Stime
	if stime == "" {
		stime = fixtureTime
	}
	susec := 0
	if e.SUsec != nil {
		susec = *e.SUsec
	}
	realm := e.Realm
	if realm == "" {
		realm = "EXAMPLE.TEST"
	}
	parts := [][]byte{
		derCtx(0, derInteger(5)),
		derCtx(1, derInteger(30)),
	}
	if e.CTime != "" {
		parts = append(parts, derCtx(2, derGeneralizedTime(e.CTime)))
		if e.CUsec != nil {
			parts = append(parts, derCtx(3, derInteger(*e.CUsec)))
		}
	}
	parts = append(parts,
		derCtx(4, derGeneralizedTime(stime)),
		derCtx(5, derInteger(susec)),
		derCtx(6, derInteger(*e.ErrorCode)),
	)
	if e.CRealm != "" {
		parts = append(parts, derCtx(7, derGStr(e.CRealm)))
	}
	if len(e.CName) > 0 {
		nameType := fixtureNameType
		if e.NameType != nil {
			nameType = *e.NameType
		}
		parts = append(parts, derCtx(8, principalName(nameType, e.CName)))
	}
	parts = append(parts, derCtx(9, derGStr(realm)))
	if len(e.SName) > 0 {
		nameType := fixtureNameType
		if e.NameType != nil {
			nameType = *e.NameType
		}
		parts = append(parts, derCtx(10, principalName(nameType, e.SName)))
	}
	if e.EText != "" {
		parts = append(parts, derCtx(12, derGStr(e.EText)))
	}
	return derApp(30, derSeq(parts...)), nil
}

// buildMessage renders one event's full DER（body 覆盖优先——opaque fixture
// 逃生口）。msgType 为一致性校验后的权威值（裁定6）。
func buildMessage(e *core.KerberosEvent) ([]byte, error) {
	if e.Body != "" {
		return hexBytes(e.Body, "body")
	}
	kt, ok := kindTable[e.Kind]
	if !ok {
		return nil, fmt.Errorf("kerberos: unknown event kind %q (kind)", e.Kind)
	}
	if e.MsgType != nil && *e.MsgType != kt.msgType {
		return nil, fmt.Errorf("kerberos: declared msg_type %d does not match kind %q (tag %d/msg-type %d) (tag)", *e.MsgType, e.Kind, kt.tag, kt.msgType)
	}
	switch e.Kind {
	case "as_req", "tgs_req":
		return kdcReq(kt.tag, kt.msgType, e)
	case "as_rep", "tgs_rep":
		return kdcRep(kt.tag, kt.msgType, e), nil
	case "ap_req":
		return apReq(e), nil
	case "ap_rep":
		return apRep(e), nil
	case "krb_error":
		return krbError(e)
	}
	return nil, fmt.Errorf("kerberos: unknown event kind %q (kind)", e.Kind)
}

// hexBytes decodes a fixture hex string（奇长/非 hex 拒；stdlib hex 收编，
// 错误锚词保持奇长/非 hex 两面）。
func hexBytes(s, what string) ([]byte, error) {
	out, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		if len(s)%2 != 0 {
			return nil, fmt.Errorf("kerberos: %s hex %q has odd length", what, s)
		}
		return nil, fmt.Errorf("kerberos: %s hex %q has non-hex character", what, s)
	}
	return out, nil
}

// ---- TCP 分帧（裁定7）----

// tcpFrame prepends the 4-byte BE record length（不含自身——RFC 4120 §6）。
func tcpFrame(msg []byte) []byte {
	out := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(out, uint32(len(msg)))
	copy(out[4:], msg)
	return out
}

// ---- 事件渲染（双载体分帧入口）----

type frame struct {
	up    bool
	bytes []byte
}

// renderEvent resolves one event to its wire form（carrier=tcp 时前置 4B
// 长度；udp 原样——datagram 边界即消息边界）。
func renderEvent(e *core.KerberosEvent, carrier string) (frame, error) {
	msg, err := buildMessage(e)
	if err != nil {
		return frame{}, err
	}
	if carrier == "tcp" {
		msg = tcpFrame(msg)
	}
	return frame{up: e.Up, bytes: msg}, nil
}

// resolveCarrier 从补全链读载体（kerberos 前一层 udp 或 tcp；缺省/非法=守卫拒）。
func resolveCarrier(chain []layers.Layer) (string, error) {
	for _, l := range chain {
		switch l.Name {
		case "kerberos":
			return "", fmt.Errorf("kerberos: no carrier layer before kerberos in chain (carrier)")
		case "tcp":
			return "tcp", nil
		case "udp":
			return "udp", nil
		}
	}
	return "", fmt.Errorf("kerberos: no udp/tcp carrier in chain (carrier)")
}

// ---- walker（会话状态单权威）----

// kerberosWalker 目前只承载扩展位：nonce/ticket/replay 状态为声明式 fixture
// 面（§12 动态清单——无策略动态消费面），分帧状态无跨事件耦合。保留结构
// 与 bacnet/dtls walker 同构，供后续 replay-cache 语义扩展。
type kerberosWalker struct{}

func newWalker() *kerberosWalker { return &kerberosWalker{} }

// ---- Generate（链驱动入口，dcerpc/dtls 同族）----

// KerberosGenerator is the terminal-layer generator for kerberos chains.
type KerberosGenerator struct{}

func (g *KerberosGenerator) Name() string { return "kerberos" }

// GenEvents/EmitEvent mark the event-generator face（bacnet 同款）。
func (g *KerberosGenerator) GenEvents() layers.EventGenerator { return g }
func (g *KerberosGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("kerberos generator: EmitEvent is not wired")
}

func (g *KerberosGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("kerberos generator: request is nil")
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("kerberos generator: EmitMsg is nil")
	}
	cfg := req.Meta.Kerberos
	if cfg == nil {
		cfg = &core.KerberosConfig{}
	}
	if err := (&Planner{}).Validate(core.FlowSpec{
		SrcIP:    req.Meta.SrcIP,
		DstIP:    req.Meta.DstIP,
		SrcPort:  req.Meta.SrcPort,
		DstPort:  req.Meta.DstPort,
		Kerberos: cfg,
	}); err != nil {
		return err
	}
	carrier, err := resolveCarrier(req.Chain)
	if err != nil {
		return err
	}

	// 空配置缺省基线（bacnet/dtls 家族同款）：无 sessions 发一条最小
	// AS-REQ（全 fixture 缺省），避免裸 {"kerberos":{}} 链静默 0 包。
	if len(cfg.Sessions) == 0 {
		base := core.KerberosEvent{Kind: "as_req", Up: true}
		fr, err := renderEvent(&base, carrier)
		if err != nil {
			return err
		}
		return req.EmitMsg(layers.MessageEvent{Up: fr.up, Bytes: fr.bytes})
	}
	// 会话端点覆盖（dtls 同款）：up 直落 SrcIP/SrcPort；down 会话声明
	// SrcIP 时显式路由 服务端(=流 dst)→客户端（多会话双客户端应答回对端）。
	for si := range cfg.Sessions {
		sess := &cfg.Sessions[si]
		_ = newWalker() // 逐会话独立状态（结构占位，见 walker 注释）
		for ei := range sess.Events {
			fr, err := renderEvent(&sess.Events[ei], carrier)
			if err != nil {
				return fmt.Errorf("kerberos: sessions[%d].events[%d]: %w", si, ei, err)
			}
			ev := layers.MessageEvent{Up: fr.up, Bytes: fr.bytes}
			if fr.up {
				if sess.SrcIP != "" {
					ev.SrcIP = sess.SrcIP
				}
				if sess.SrcPort != 0 {
					ev.SrcPort = sess.SrcPort
				}
			} else if sess.SrcIP != "" {
				ev.SrcIP = req.Meta.DstIP
				ev.DstIP = sess.SrcIP
				ev.OverrideDstIP = true
			}
			if sess.DstPort != 0 {
				ev.DstPort = sess.DstPort
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err := req.EmitMsg(ev); err != nil {
				return err
			}
		}
	}
	return nil
}

// BuildFrames renders all sessions' events in replay order（链级红例与
// Generate 共用；carrier 由调用方声明）。
func BuildFrames(cfg *core.KerberosConfig, carrier string) ([][]frame, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kerberos: config is nil")
	}
	if len(cfg.Sessions) == 0 {
		base := core.KerberosEvent{Kind: "as_req", Up: true}
		fr, err := renderEvent(&base, carrier)
		if err != nil {
			return nil, err
		}
		return [][]frame{{fr}}, nil
	}
	var out [][]frame
	for si := range cfg.Sessions {
		var frames []frame
		for ei := range cfg.Sessions[si].Events {
			fr, err := renderEvent(&cfg.Sessions[si].Events[ei], carrier)
			if err != nil {
				return nil, fmt.Errorf("kerberos: sessions[%d].events[%d]: %w", si, ei, err)
			}
			frames = append(frames, fr)
		}
		out = append(out, frames)
	}
	return out, nil
}

// init registers the generator + validator（bacnet 同款接线）。
func init() {
	layers.RegisterLayerGenerator("kerberos", func() (layers.LayerGenerator, error) { return &KerberosGenerator{}, nil })
	layers.RegisterLayerValidator("kerberos", func(spec *core.FlowSpec) error { return (&Planner{}).Validate(*spec) })
}
