// Package ntlm — NTLM（MS-NLMP）NTLMv2 三消息终结层（D-NTLM-1 #45）。
//
// Register* functions run at init() time (in builder.go), wiring the ntlm
// layer into the chain planner and generator factory. The side-effect import
// _ "…/protocol/ntlm" activates this registration.
//
// 链形（裁定 N1）：P-SMB `[ip,tcp,ntlm]`；P-HTTP `[ip,tcp,http,ntlm]`
// （http 作可选底座，透传变换器原样转发——两 profile 均由本层自封帧，
// `OptionalOn ["http"]` 只是允许显式声明底座）。NTLMSSP 三消息固定头 +
// SecurityBuffer `Len|MaxLen|Offset`（little-endian，offset 相对 NTLMSSP
// 起点——契约 §4/§5）。
//
// 密钥面 opaque（契约 §7）：proof/MIC/EncryptedRandomSessionKey 无授权密钥
// 不生成也不断言其值，线上为确定性占位字节（fixtureFill），用例只钉长度/
// 边界与固定头。
package ntlm

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// NTLMSSP 通用头与消息类型（契约 §4，MS-NLMP §2.2.1）。
const (
	ntlmSignature    = "NTLMSSP\x00"
	typeNegotiate    = 1
	typeChallenge    = 2
	typeAuthenticate = 3
)

// flags 位（契约 §6；little-endian 32-bit 集合）。
const (
	flagUnicode                 uint32 = 0x00000001
	flagRequestTarget           uint32 = 0x00000004
	flagSign                    uint32 = 0x00000010
	flagNTLM                    uint32 = 0x00000200
	flagAlwaysSign              uint32 = 0x00008000
	flagTargetTypeDomain        uint32 = 0x00010000
	flagExtendedSessionSecurity uint32 = 0x00080000
	flagTargetInfo              uint32 = 0x00800000
	flagVersion                 uint32 = 0x02000000
	flagNegotiate128            uint32 = 0x20000000
	flagKeyExch                 uint32 = 0x40000000
	flagNegotiate56             uint32 = 0x80000000
)

// fixture 缺省（契约 §2 形态；最小可辨识档）。
const (
	fixtureFill        = 0xA5 // proof/MIC/session key opaque 占位字节（密钥面不伪造）
	fixtureDomain      = "EXAMPLE"
	fixtureUser        = "user"
	fixtureWorkstation = "WORKSTATION"
	fixtureNbComputer  = "WIN-DC01"
	fixtureNbDomain    = "EXAMPLE"
	fixtureDnsComputer = "dc01.example.test"
	fixtureDnsDomain   = "example.test"
	// fixtureTimeBase 是确定性时间戳基准（2026-09-24 12:00:00 UTC 的 FILETIME
	// ——运行期时间不进硬编码常量面：按会话确定性派生，用例只断 nonzero）。
	fixtureTimeBase int64 = 134267688000000000
	// 缺省 flags 档 = UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|
	// TARGET_TYPE_DOMAIN|EXTENDED_SESSIONSECURITY|TARGET_INFO|128|56
	// （= 0xA0898205；resolveFlags(nil) 即此档，链级红例逐位钉）。
)

// SMB2 常量（MS-SMB2 §2.2.1.2/§3.2.5.3；P-SMB 成帧=内建 NTLMSSP 实现
// `internal/protocol/smb` 的字节参照——G-NTLM-3 划界：本层独立自封，
// 不依赖 smb 层也不进 smb 链）。
const (
	smb2HeaderSize                    = 64
	smb2CmdSessionSetup        uint16 = 0x0001
	smb2StatusSuccess          uint32 = 0x00000000
	smb2StatusMoreProcessing   uint32 = 0xC0000016
	smb2StatusLogonFailure     uint32 = 0xC000006D
	smb2Credits                       = 31
	smb2SessionSetupReqOffset         = smb2HeaderSize + 24 // 88
	smb2SessionSetupRespOffset        = smb2HeaderSize + 8  // 72
)

// ---- flags 解析 ----

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// resolveFlags 求 Type 1/2/3 共用的 flags 值（三消息交集一致——契约 §2
// flags 行；指针三态：缺席=缺省档、显式 false=关闭）。
func resolveFlags(f *core.NTLMFlags) uint32 {
	var v uint32
	var c core.NTLMFlags
	if f != nil {
		c = *f
	}
	set := func(p *bool, bit uint32, def bool) {
		if boolOr(p, def) {
			v |= bit
		}
	}
	set(c.Unicode, flagUnicode, true)
	set(c.RequestTarget, flagRequestTarget, true)
	set(c.NTLM, flagNTLM, true)
	set(c.AlwaysSign, flagAlwaysSign, true)
	set(c.TargetTypeDomain, flagTargetTypeDomain, true)
	set(c.ExtendedSessionSecurity, flagExtendedSessionSecurity, true)
	set(c.TargetInfo, flagTargetInfo, true)
	set(c.Version, flagVersion, false)
	set(c.Sign, flagSign, false)
	set(c.KeyExch, flagKeyExch, false)
	set(c.Negotiate128, flagNegotiate128, true)
	set(c.Negotiate56, flagNegotiate56, true)
	return v
}

// ---- 编码原语 ----

// strBytes 按 flags 编码字符串：Unicode → UTF-16LE（长度必为偶数——契约 §5
// 规则 3）；关闭 → OEM（latin-1 逐字节）。
func strBytes(s string, flags uint32) []byte {
	if flags&flagUnicode == 0 {
		// OEM 面：latin-1 单字节（U+0080..U+00FF 折单字节；>U+00FF 已被
		// validateFlags 拒，此处截断为 ? 兜底不静默多字节）。
		out := make([]byte, 0, len(s))
		for _, r := range s {
			if r > 0xFF {
				out = append(out, '?')
				continue
			}
			out = append(out, byte(r))
		}
		return out
	}
	out := make([]byte, 0, 2*len(s))
	for _, r := range s {
		if r > 0xFFFF { // 基本多文种平面外按代理对（UTF-16）
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
			continue
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// secBuf 是一个 security buffer 三元组（契约 §5）。
type secBuf struct {
	length uint16
	maxLen uint16
	offset uint32
}

func putSecBuf(b []byte, at int, s secBuf) {
	binary.LittleEndian.PutUint16(b[at:at+2], s.length)
	binary.LittleEndian.PutUint16(b[at+2:at+4], s.maxLen)
	binary.LittleEndian.PutUint32(b[at+4:at+8], s.offset)
}

// payloadBuilder 按声明顺序累加 security buffer 负载，逐字段回填三元组
// （offset 相对 NTLMSSP 起点；空字段 Len=0/MaxLen=0、offset=当前 payload 起点
// ——契约 §5 规则 2 的"实现约定"，验证器不得以其推导 payload）。
type payloadBuilder struct {
	buf    []byte
	base   int // payload 起点（固定头长度）
	maxPad int
}

func newPayloadBuilder(base, maxPad int) *payloadBuilder {
	return &payloadBuilder{buf: make([]byte, 0, 128), base: base, maxPad: maxPad}
}

// add 追加一段负载并返回其 security buffer（maxLen: 非空字段 = len+maxPad）。
func (p *payloadBuilder) add(b []byte) secBuf {
	off := p.base + len(p.buf)
	p.buf = append(p.buf, b...)
	sb := secBuf{length: uint16(len(b)), offset: uint32(off)}
	if len(b) > 0 {
		sb.maxLen = uint16(len(b) + p.maxPad)
	}
	return sb
}

// empty 返回空字段的三元组（Len=0；offset=payload 边界）。
func (p *payloadBuilder) empty() secBuf {
	return secBuf{length: 0, maxLen: 0, offset: uint32(p.base + len(p.buf))}
}

// bytes 返回完整负载。
func (p *payloadBuilder) bytes() []byte { return p.buf }

// ---- AV_PAIR 序列（契约 §6）----

const (
	avIdEOL         uint16 = 0x0000
	avIdNbComputer  uint16 = 1
	avIdNbDomain    uint16 = 2
	avIdDnsComputer uint16 = 3
	avIdDnsDomain   uint16 = 4
	avIdDnsTree     uint16 = 5
	avIdFlags       uint16 = 6
	avIdTimestamp   uint16 = 7
	avIdTargetName  uint16 = 9
)

// avPair 渲染一项：AvId(2) | AvLen(2) | Value（little-endian；AvLen 只计
// value，不含 4-byte header）。
func avPair(id uint16, value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(out[0:2], id)
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(value)))
	copy(out[4:], value)
	return out
}

// avEOL 是序列收尾项（MsvAvEOL=0, AvLen=0——契约 §6 必须项）。
func avEOL() []byte { return avPair(avIdEOL, nil) }

// avText 按 unicode flag 编码文本 value。
func avText(id uint16, s string, flags uint32) []byte {
	return avPair(id, strBytes(s, flags))
}

// avExtra 渲染配置声明的未知/扩展 AV 项（Text 或 ValueHex 二选一）。
func avExtra(p core.NTLMAVPair, flags uint32) ([]byte, error) {
	switch {
	case p.Text != "" && p.ValueHex != "":
		return nil, fmt.Errorf("ntlm: av pair id %d declares both text and value_hex (av)", p.ID)
	case p.Text != "":
		return avText(p.ID, p.Text, flags), nil
	case p.ValueHex != "":
		raw, err := hexBytes(p.ValueHex, fmt.Sprintf("av pair id %d value_hex", p.ID))
		if err != nil {
			return nil, err
		}
		return avPair(p.ID, raw), nil
	default:
		return avPair(p.ID, nil), nil
	}
}

// ---- 会话确定性状态（§16.12：rand(seed+序号可复现)；多会话/多流互不相同） ----

type sessionState struct {
	id     uint64
	msgID  uint64
	server [8]byte
	client [8]byte
	blobTS int64
}

// seedFor 由流四元组 + 会话序号派生确定性种子（同输入必同输出=可复现；
// 流间 src_port 默认递增 → 多流 challenge 互不相同）。
func seedFor(srcPort, dstPort uint16, si int) int64 {
	return int64(uint64(srcPort)<<48 ^ uint64(dstPort)<<32 ^ uint64(uint16(si))<<16 ^ 0x4E544C4D)
}

// newSessionState 建立会话状态：ServerChallenge/client challenge/blob 时间戳
// 在会话起点各抽一次（重发同一消息 = 同字节——契约 §9 重试语义）。
func newSessionState(srcPort, dstPort uint16, si int) *sessionState {
	r := rand.New(rand.NewSource(seedFor(srcPort, dstPort, si)))
	st := &sessionState{}
	for i := range st.server {
		st.server[i] = byte(r.Intn(256))
	}
	if st.server == [8]byte{} { // 全零 challenge 非法（契约 §6 nonzero）
		st.server[7] = 1
	}
	for i := range st.client {
		st.client[i] = byte(r.Intn(256))
	}
	if st.client == [8]byte{} {
		st.client[7] = 2
	}
	st.blobTS = fixtureTimeBase + int64(r.Intn(1<<20))
	st.id = r.Uint64()
	if st.id == 0 {
		st.id = 1
	}
	return st
}

// hexBytes 解码 fixture hex 串（奇长/非 hex 拒；kerberos 同款双锚词）。
func hexBytes(s, what string) ([]byte, error) {
	out, err := hex.DecodeString(strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")))
	if err != nil {
		if len(s)%2 != 0 {
			return nil, fmt.Errorf("ntlm: %s hex %q has odd length", what, s)
		}
		return nil, fmt.Errorf("ntlm: %s hex %q has non-hex character", what, s)
	}
	return out, nil
}

// hexOrAuto 解析 "auto"/空（走确定性派生）或 16-hex fixture 钉值。
func hexOrAuto(v, what string, auto [8]byte) ([8]byte, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto":
		return auto, nil
	}
	raw, err := hexBytes(v, what)
	if err != nil {
		return [8]byte{}, err
	}
	if len(raw) != 8 {
		return [8]byte{}, fmt.Errorf("ntlm: %s hex %q is %d bytes, want 8 (length)", what, v, len(raw))
	}
	var out [8]byte
	copy(out[:], raw)
	return out, nil
}

// ---- 三消息 builder ----

// versionField 渲染 8-byte Version（MS-NLMP §2.2.2.10：Major=10, Minor=0,
// Build=0, Reserved=0, NTLMRevisionCurrent=15）——仅 NEGOTIATE_VERSION 置位
// 时出现（契约 §4.1–§4.3）。
func versionField() []byte {
	return []byte{10, 0, 0, 0, 0, 0, 0, 0x0F}
}

// buildType1 渲染 NEGOTIATE_MESSAGE（契约 §4.1）：
// Signature(8) | Type(4) | Flags(4) | DomainFields(8) | WorkstationFields(8)
// | Version(8,可选) | Payload。
func buildType1(sess *core.NTLMSession, cfg *core.NTLMConfig, flags uint32, st *sessionState) []byte {
	domain := sess.Domain
	if domain == "" {
		domain = fixtureDomain
	}
	ws := sess.Workstation
	if ws == "" {
		ws = fixtureWorkstation
	}
	header := 32
	if flags&flagVersion != 0 {
		header = 40
	}
	p := newPayloadBuilder(header, 0)
	domainSB := p.add(strBytes(domain, flags))
	wsSB := p.add(strBytes(ws, flags))
	payload := p.bytes()

	out := make([]byte, header, header+len(payload))
	copy(out[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(out[8:12], typeNegotiate)
	binary.LittleEndian.PutUint32(out[12:16], flags)
	putSecBuf(out, 16, domainSB)
	putSecBuf(out, 24, wsSB)
	if header == 40 {
		copy(out[32:40], versionField())
	}
	return append(out, payload...)
}

// buildType2 渲染 CHALLENGE_MESSAGE（契约 §4.2）：
// Signature(8) | Type(4) | TargetNameFields(8) | Flags(4) | ServerChallenge(8)
// | Reserved(8) | TargetInfoFields(8) | Version(8,可选) | Payload(TargetName,
// TargetInfo)。
func buildType2(sess *core.NTLMSession, cfg *core.NTLMConfig, flags uint32, st *sessionState) ([]byte, error) {
	targetName := sess.TargetName
	header := 48
	if flags&flagVersion != 0 {
		header = 56
	}
	p := newPayloadBuilder(header, 0)
	var tnSB secBuf
	if flags&flagTargetInfo != 0 && targetName != "" {
		tnSB = p.add(strBytes(targetName, flags))
	} else {
		tnSB = p.empty()
	}
	// TARGET_INFO 置位才渲染 AV 序列；关闭时 TargetInfo 为空（与 validateFlags
	// 一致——flag 关 + target_info 声明 = 协商不一致拒；flag 关 + 无声明 =
	// 空 TargetInfo，不渲染缺省 AV）。
	var tiSB secBuf
	if flags&flagTargetInfo != 0 {
		avs, err := buildTargetInfoAVs(cfg.TargetInfo, flags, st)
		if err != nil {
			return nil, err
		}
		if len(avs) > 0 {
			tiSB = p.add(avs)
		} else {
			tiSB = p.empty()
		}
	} else {
		tiSB = p.empty()
	}
	payload := p.bytes()

	out := make([]byte, header, header+len(payload))
	copy(out[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(out[8:12], typeChallenge)
	putSecBuf(out, 12, tnSB)
	binary.LittleEndian.PutUint32(out[20:24], flags)
	copy(out[24:32], st.server[:])
	// Reserved(8B) 保持全零（契约 §4.2：不得承载伪造 proof）。
	putSecBuf(out, 40, tiSB)
	if header == 56 {
		copy(out[48:56], versionField())
	}
	return append(out, payload...), nil
}

// buildTargetInfoAVs 渲染 Type 2 TargetInfo 的 AV_PAIR 序列（契约 §6）。
func buildTargetInfoAVs(ti *core.NTLMTargetInfo, flags uint32, st *sessionState) ([]byte, error) {
	var c core.NTLMTargetInfo
	if ti != nil {
		c = *ti
	}
	// NTLMv2 需要 TargetInfo（ESS 档）；sequence 至少含域信息。
	nbComputer := c.NbComputerName
	if nbComputer == "" {
		nbComputer = fixtureNbComputer
	}
	nbDomain := c.NbDomainName
	if nbDomain == "" {
		nbDomain = fixtureNbDomain
	}
	var out []byte
	out = append(out, avText(avIdNbComputer, nbComputer, flags)...)
	out = append(out, avText(avIdNbDomain, nbDomain, flags)...)
	if c.DnsComputerName != "" {
		out = append(out, avText(avIdDnsComputer, c.DnsComputerName, flags)...)
	} else {
		out = append(out, avText(avIdDnsComputer, fixtureDnsComputer, flags)...)
	}
	if c.DnsDomainName != "" {
		out = append(out, avText(avIdDnsDomain, c.DnsDomainName, flags)...)
	} else {
		out = append(out, avText(avIdDnsDomain, fixtureDnsDomain, flags)...)
	}
	if c.DnsTreeName != "" {
		out = append(out, avText(avIdDnsTree, c.DnsTreeName, flags)...)
	}
	if c.AvFlags != nil {
		v := make([]byte, 4)
		binary.LittleEndian.PutUint32(v, *c.AvFlags)
		out = append(out, avPair(avIdFlags, v)...)
	}
	if c.TargetName != "" {
		out = append(out, avText(avIdTargetName, c.TargetName, flags)...)
	}
	// MsvAvTimestamp（FILETIME 8B，确定性派生——运行期时间不硬编码）。
	autoTS := make([]byte, 8)
	binary.LittleEndian.PutUint64(autoTS, uint64(st.blobTS))
	ts, err := hexOrAuto(c.Timestamp, "target_info.timestamp", [8]byte{})
	if err != nil {
		return nil, err
	}
	if c.Timestamp == "" || strings.EqualFold(strings.TrimSpace(c.Timestamp), "auto") {
		ts = [8]byte{}
		copy(ts[:], autoTS)
	}
	tsBytes := make([]byte, 8)
	copy(tsBytes, ts[:])
	out = append(out, avPair(avIdTimestamp, tsBytes)...)
	for _, ex := range c.Extra {
		raw, err := avExtra(ex, flags)
		if err != nil {
			return nil, err
		}
		out = append(out, raw...)
	}
	if !c.NoEOL {
		out = append(out, avEOL()...)
	}
	return out, nil
}

// buildNTLMv2Blob 渲染 NTLMv2_RESPONSE（契约 §7；MS-NLMP §2.2.2.1）：
// Proof(16) | RespType(1) | HiRespType(1) | Reserved1(2) | Reserved2(4) |
// TimeStamp(8) | ChallengeFromClient(8) | Reserved3(4) | AvPairs | EOL(4)。
// Proof 无授权密钥 = 确定性 opaque 占位（不伪造 HMAC-MD5 值）。
func buildNTLMv2Blob(t3 *core.NTLMType3Config, flags uint32, st *sessionState) ([]byte, error) {
	var c core.NTLMType3Config
	if t3 != nil {
		c = *t3
	}
	rv, hrv := 1, 1
	if c.ResponseVersion != nil {
		rv = *c.ResponseVersion
	}
	if c.HiResponseVersion != nil {
		hrv = *c.HiResponseVersion
	}
	cc, err := hexOrAuto(c.ClientChallenge, "ntlmv2_response.client_challenge", st.client)
	if err != nil {
		return nil, err
	}
	var ts int64 = st.blobTS
	if strings.EqualFold(strings.TrimSpace(c.Timestamp), "auto") || strings.TrimSpace(c.Timestamp) == "" {
		// 沿用会话确定性时间戳
	} else {
		raw, err := hexBytes(c.Timestamp, "ntlmv2_response.timestamp")
		if err != nil {
			return nil, err
		}
		if len(raw) != 8 {
			return nil, fmt.Errorf("ntlm: ntlmv2_response.timestamp hex %q is %d bytes, want 8 (length)", c.Timestamp, len(raw))
		}
		ts = int64(binary.LittleEndian.Uint64(raw))
	}

	avs, err := blobAVPairs(c.AVPairs, flags, st)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 0, 16+28+len(avs)+4)
	proof := make([]byte, 16)
	for i := range proof {
		proof[i] = fixtureFill
	}
	blob = append(blob, proof...)
	blob = append(blob, byte(rv), byte(hrv), 0, 0) // RespType|HiRespType|Reserved1(2)
	blob = append(blob, 0, 0, 0, 0)                // Reserved2(4)——MS-NLMP §2.2.2.1
	tsb := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsb, uint64(ts))
	blob = append(blob, tsb...)
	blob = append(blob, cc[:]...)
	blob = append(blob, 0, 0, 0, 0) // Reserved3(4)
	blob = append(blob, avs...)
	if !c.NoEOL {
		blob = append(blob, avEOL()...)
	}
	return blob, nil
}

// blobAVPairs 渲染 blob 内 AV 序列（未知项按扩展保留；EOL 由调用方收尾）。
func blobAVPairs(pairs []core.NTLMAVPair, flags uint32, st *sessionState) ([]byte, error) {
	if len(pairs) == 0 {
		// 缺省：会话确定性时间戳一项（NTLMv2 常态最小 AV 集）。
		tsb := make([]byte, 8)
		binary.LittleEndian.PutUint64(tsb, uint64(st.blobTS))
		return avPair(avIdTimestamp, tsb), nil
	}
	var out []byte
	for _, p := range pairs {
		raw, err := avExtra(p, flags)
		if err != nil {
			return nil, err
		}
		out = append(out, raw...)
	}
	return out, nil
}

// buildType3 渲染 AUTHENTICATE_MESSAGE（契约 §4.3）：
// Signature(8) | Type(4) | LmFields(8) | NtFields(8) | DomainFields(8) |
// UserFields(8) | WorkstationFields(8) | SessionKeyFields(8) | Flags(4) |
// Version(8,可选) | MIC(16,可选) | Payload。
func buildType3(sess *core.NTLMSession, cfg *core.NTLMConfig, flags uint32, st *sessionState,
	micPresent bool, sessionKeyLen int) ([]byte, error) {

	domain := sess.Domain
	if domain == "" {
		domain = fixtureDomain
	}
	user := sess.User
	if user == "" {
		user = fixtureUser
	}
	ws := sess.Workstation
	if ws == "" {
		ws = fixtureWorkstation
	}
	var t3 *core.NTLMType3Config
	if cfg != nil {
		t3 = cfg.Type3
	}
	blob, err := buildNTLMv2Blob(t3, flags, st)
	if err != nil {
		return nil, err
	}
	var lm []byte
	lmLen := 0
	if t3 != nil {
		lmLen = t3.LMResponseLen
	}
	if lmLen < 0 {
		return nil, fmt.Errorf("ntlm: ntlmv2_response.lm_response_len %d is negative (length)", lmLen)
	}
	if lmLen > 0 {
		lm = make([]byte, lmLen)
		for i := range lm {
			lm[i] = fixtureFill
		}
	}
	maxPad := 0
	if t3 != nil {
		maxPad = t3.MaxLenPad
		if maxPad < 0 {
			return nil, fmt.Errorf("ntlm: ntlmv2_response.max_len_pad %d is negative (length)", maxPad)
		}
	}

	header := 64
	if flags&flagVersion != 0 {
		header += 8
	}
	if micPresent {
		header += 16
	}
	p := newPayloadBuilder(header, maxPad)
	lmSB := p.empty()
	if len(lm) > 0 {
		lmSB = p.add(lm)
	}
	ntSB := p.add(blob)
	domainSB := p.add(strBytes(domain, flags))
	userSB := p.add(strBytes(user, flags))
	wsSB := p.add(strBytes(ws, flags))
	var skSB secBuf
	if sessionKeyLen > 0 {
		sk := make([]byte, sessionKeyLen)
		for i := range sk {
			sk[i] = uint8(fixtureFill ^ (i * 7))
		}
		skSB = p.add(sk)
	} else {
		skSB = p.empty()
	}
	payload := p.bytes()

	out := make([]byte, header, header+len(payload))
	copy(out[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(out[8:12], typeAuthenticate)
	putSecBuf(out, 12, lmSB)
	putSecBuf(out, 20, ntSB)
	putSecBuf(out, 28, domainSB)
	putSecBuf(out, 36, userSB)
	putSecBuf(out, 44, wsSB)
	putSecBuf(out, 52, skSB)
	binary.LittleEndian.PutUint32(out[60:64], flags)
	off := 64
	if flags&flagVersion != 0 {
		copy(out[64:72], versionField())
		off = 72
	}
	if micPresent {
		for i := 0; i < 16; i++ {
			out[off+i] = uint8(fixtureFill + i)
		}
	}
	return append(out, payload...), nil
}

// ---- SPNEGO 外层（RFC 4178；契约 §8 隔离面）----

// ntlmOID 是 NTLM 机制的 SPNEGO OID（1.3.6.1.4.1.311.2.2.10）。
var ntlmOID = []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}

// spnegoOID 是 SPNEGO 机制 OID（1.3.6.1.5.5.2）。
var spnegoOID = []byte{0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}

func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xFF:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func tlv(tag byte, content []byte) []byte {
	out := make([]byte, 0, 2+len(content))
	out = append(out, tag)
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

// wrapSPNEGO 把 NTLMSSP token 包进 SPNEGO 外层（Type 1 = GSS-API
// InitialContextToken + negTokenInit；Type 2/3 = negTokenResp——现网 SMB2/
// HTTP 双态）。ASN.1 tag/length 与 NTLM SecurityBuffer 严格分离（契约 §8）：
// 内层 NTLMSSP signature 只出现在 mechToken/responseToken 起点。
func wrapSPNEGO(token []byte, msgType int) []byte {
	switch msgType {
	case typeNegotiate:
		// RFC 4178 NegTokenInit ::= SEQUENCE { mechTypes [0] SEQUENCE OF
		// OID, mechToken [2] OCTET STRING }：[0] 内是 SEQUENCE OF（30），
		// 不是裸 OID；直接塞 OID 会触发 dissector BER 伪影（P5 lane 实修——
		// 既有 smb 层 buildGSSAPIBlob 同口径：mtSeq=30{06 len OID}）。
		mechList := tlv(0x30, ntlmOID)                             // SEQUENCE OF OID
		mechTypes := tlv(0xA0, mechList)                           // [0] MechTypeList
		mechToken := tlv(0xA2, tlv(0x04, token))                   // [2] OCTET STRING
		negTokenInit := tlv(0x30, append(mechTypes, mechToken...)) // NegTokenInit SEQUENCE
		inner := append(append([]byte{}, spnegoOID...), negTokenInit...)
		return tlv(0x60, inner) // GSS-API InitialContextToken [APPLICATION 0]
	default:
		// negTokenResp: negState [0] ENUMERATED, supportedMech [1] OID,
		// responseToken [2] OCTET STRING。
		// tshark 的 spnego 分解器要 [1] 内是显式 SEQUENCE（P5 lane 实修：
		// 直接塞 context 序列触发 "Sequence expected but class:CONTEXT ...
		// tag:0 was unexpected" 的 BER 伪影——与 GSS initial token 面同口径）。
		state := tlv(0xA0, tlv(0x0A, []byte{byte(msgTypeState(msgType))})) // negState [0] ENUMERATED
		mech := tlv(0xA1, ntlmOID)                                         // supportedMech [1] OID
		resp := tlv(0xA2, tlv(0x04, token))                                // responseToken [2] OCTET STRING
		seq := append(append([]byte{}, state...), mech...)
		seq = append(seq, resp...)
		return tlv(0xA1, tlv(0x30, seq)) // [1] negTokenResp（显式 SEQUENCE）
	}
}

// msgTypeState 给 negTokenResp 的 negState（RFC 4178 §4.2.2：
// 1=accept-incomplete（Type 2 中间态）、0=accept-completed（Type 3 终态））。
func msgTypeState(msgType int) uint8 {
	if msgType == typeAuthenticate {
		return 0
	}
	return 1
}

// ---- 双 profile 成帧 ----

// frameSMB2 渲染一轮 SMB2 PDU：NBSS(4) + SMB2 header(64) + SESSION_SETUP
// body + SecurityBuffer(token)（MS-SMB2 §2.2.1.2/§3.2.5.3；字节布局对齐
// 既有 smb 层实现 `internal/protocol/smb`——G-NTLM-3 参考权威，本层独立
// 自封不共用代码）。
func frameSMB2(kind string, token []byte, st *sessionState) ([]byte, error) {
	var status uint32
	var req bool
	switch kind {
	case "negotiate", "authenticate":
		req = true
		status = smb2StatusSuccess
	case "challenge":
		status = smb2StatusMoreProcessing
	case "session_setup_success":
		status = smb2StatusSuccess
	case "session_setup_failure":
		status = smb2StatusLogonFailure
	default:
		return nil, fmt.Errorf("ntlm: event kind %q is not a smb2 carrier event (profile)", kind)
	}

	hdr := make([]byte, smb2HeaderSize)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0xFE, 0x53, 0x4D, 0x42
	binary.LittleEndian.PutUint16(hdr[4:6], smb2HeaderSize)
	binary.LittleEndian.PutUint16(hdr[6:8], 1) // CreditCharge
	binary.LittleEndian.PutUint32(hdr[8:12], status)
	binary.LittleEndian.PutUint16(hdr[12:14], smb2CmdSessionSetup)
	binary.LittleEndian.PutUint16(hdr[14:16], smb2Credits)
	// Flags bit0 = SERVER_TO_REDIR（MS-SMB2 §2.2.1.2）：响应方向必须置位，
	// 否则 tshark 按 request 解码 SESSION_SETUP response → Malformed
	// （P5 lane 实修——响应面 StructureSize=9 被读成 request 固定体）。
	if !req {
		binary.LittleEndian.PutUint32(hdr[16:20], 0x00000001)
	}
	binary.LittleEndian.PutUint64(hdr[24:32], st.msgID)
	// SessionId：首个 SESSION_SETUP request 用 0（会话尚未建立），此后用
	// 服务端分配的会话 ID——与既有 smb 层实现（emit_session.go：
	// round 0 请求后 nextSessionID）字节口径一致。
	sessionID := st.id
	if req && st.msgID == 0 {
		sessionID = 0
	}
	binary.LittleEndian.PutUint64(hdr[40:48], sessionID)
	// Flags/NextCommand/TreeId/Signature 全零（未签名、无链式命令）。

	var body []byte
	if req {
		body = make([]byte, 24, 24+len(token))
		body[0] = 0x19 // StructureSize = 25
		body[3] = 0x01 // SecurityMode: signing enabled
		binary.LittleEndian.PutUint16(body[12:14], smb2SessionSetupReqOffset)
		binary.LittleEndian.PutUint16(body[14:16], uint16(len(token)))
		body = append(body, token...)
	} else {
		body = make([]byte, 8, 8+len(token))
		body[0] = 0x09 // StructureSize = 9
		if len(token) > 0 {
			binary.LittleEndian.PutUint16(body[4:6], smb2SessionSetupRespOffset)
			binary.LittleEndian.PutUint16(body[6:8], uint16(len(token)))
			body = append(body, token...)
		} else if kind != "session_setup_failure" {
			// SUCCESS 响应：SecurityBufferOffset = 72 + Length = 0（真实服务器
			// 形态）；LOGON_FAILURE 错误响应保持 0/0（smb 层错误体口径）。
			binary.LittleEndian.PutUint16(body[4:6], smb2SessionSetupRespOffset)
		}
	}

	pduLen := len(hdr) + len(body)
	out := make([]byte, 0, 4+pduLen)
	out = append(out, 0x00, byte(pduLen>>16), byte(pduLen>>8), byte(pduLen))
	out = append(out, hdr...)
	out = append(out, body...)
	// request/response 共用 MessageId，下一轮才递增（既有 smb 层 BUG #5 教训）。
	if !req {
		st.msgID++
	}
	return out, nil
}

// frameHTTP 渲染 HTTP/1.1 载体消息（RFC 4559）：
//   - negotiate/authenticate（up）: POST + `Authorization: Negotiate <b64>`；
//   - challenge（down）: 401 + `WWW-Authenticate: Negotiate <b64>`；
//   - challenge_401（down）: 401 + 裸 `WWW-Authenticate: Negotiate`（探测轮）；
//   - http_success（down）: 200 OK；
//   - http_unauthorized（down）: 401 + 裸 `WWW-Authenticate: Negotiate`（终态拒绝）。
func frameHTTP(kind string, token []byte, host string) ([]byte, error) {
	b64 := base64.StdEncoding.EncodeToString(token)
	switch kind {
	case "negotiate", "authenticate":
		var b strings.Builder
		b.WriteString("POST / HTTP/1.1\r\n")
		b.WriteString("Host: " + host + "\r\n")
		b.WriteString("User-Agent: trafficgen-ntlm\r\n")
		b.WriteString("Connection: keep-alive\r\n")
		b.WriteString("Content-Length: 0\r\n")
		b.WriteString("Authorization: Negotiate " + b64 + "\r\n\r\n")
		return []byte(b.String()), nil
	case "challenge":
		var b strings.Builder
		b.WriteString("HTTP/1.1 401 Unauthorized\r\n")
		b.WriteString("WWW-Authenticate: Negotiate " + b64 + "\r\n")
		b.WriteString("Content-Length: 0\r\n")
		b.WriteString("Connection: keep-alive\r\n\r\n")
		return []byte(b.String()), nil
	case "challenge_401":
		return []byte("HTTP/1.1 401 Unauthorized\r\n" +
			"WWW-Authenticate: Negotiate\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: keep-alive\r\n\r\n"), nil
	case "http_unauthorized":
		return []byte("HTTP/1.1 401 Unauthorized\r\n" +
			"WWW-Authenticate: Negotiate\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: keep-alive\r\n\r\n"), nil
	case "http_success":
		return []byte("HTTP/1.1 200 OK\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: keep-alive\r\n\r\n"), nil
	default:
		return nil, fmt.Errorf("ntlm: event kind %q is not an http-negotiate carrier event (profile)", kind)
	}
}

// ---- 事件渲染（双 profile 入口）----

type frame struct {
	up    bool
	bytes []byte
}

// renderEvent 渲染一事件：NTLMSSP token（按 kind）→ 可选 SPNEGO 外层 →
// 按 profile 成帧。
func renderEvent(kind string, sess *core.NTLMSession, cfg *core.NTLMConfig, flags uint32,
	st *sessionState, versionOn, micOn bool, keyLen int, host string) (frame, error) {

	var token []byte
	var err error
	msgType := 0
	up := false
	switch kind {
	case "negotiate":
		msgType = typeNegotiate
		up = true
		token = buildType1(sess, cfg, flags, st)
	case "challenge":
		msgType = typeChallenge
		token, err = buildType2(sess, cfg, flags, st)
	case "authenticate":
		msgType = typeAuthenticate
		up = true
		token, err = buildType3(sess, cfg, flags, st, micOn, keyLen)
	case "session_setup_success", "session_setup_failure", "challenge_401", "http_success", "http_unauthorized":
		// 纯载体事件（无 NTLMSSP token）。
	default:
		return frame{}, fmt.Errorf("ntlm: unknown event kind %q (kind)", kind)
	}
	if err != nil {
		return frame{}, err
	}
	if token != nil && (cfg == nil || cfg.Outer != "spnego") {
		// 裸 NTLMSSP（outer=none 缺省）
	} else if token != nil {
		token = wrapSPNEGO(token, msgType)
	}

	profile := profileOf(cfg)
	var wire []byte
	switch profile {
	case "smb2":
		wire, err = frameSMB2(kind, token, st)
	case "http-negotiate":
		wire, err = frameHTTP(kind, token, host)
	default:
		return frame{}, fmt.Errorf("ntlm: unknown profile %q (profile)", profile)
	}
	if err != nil {
		return frame{}, err
	}
	return frame{up: up, bytes: wire}, nil
}

// profileOf 归一 profile（空 = 缺省档 smb2）。
func profileOf(cfg *core.NTLMConfig) string {
	if cfg == nil || cfg.Profile == "" {
		return "smb2"
	}
	return cfg.Profile
}

// ---- walker（会话状态单权威：逐会话独立 challenge/msgID/时间戳） ----

type ntlmWalker struct {
	cfg     *core.NTLMConfig
	srcPort uint16
	dstPort uint16
	host    string
}

func newWalker(cfg *core.NTLMConfig, srcPort, dstPort uint16, host string) *ntlmWalker {
	return &ntlmWalker{cfg: cfg, srcPort: srcPort, dstPort: dstPort, host: host}
}

// resolveSession 求会话事件的实际参数（方向/Version/MIC/session key 覆盖）。
func (w *ntlmWalker) resolveEvent(ev *core.NTLMEvent, kind string) (up, versionOn, micOn bool, keyLen int) {
	var c core.NTLMConfig
	if w.cfg != nil {
		c = *w.cfg
	}
	// 方向缺省按 kind 派生（negotiate/authenticate=up）。
	defUp := kind == "negotiate" || kind == "authenticate"
	up = boolOr(ev.Up, defUp)
	verDef := c.Flags != nil && boolOr(c.Flags.Version, false)
	versionOn = boolOr(ev.Version, verDef)
	micDef := c.MIC != nil && *c.MIC
	micOn = boolOr(ev.MIC, micDef)
	keyLen = c.SessionKeyLen
	if ev.SessionKeyLen != nil {
		keyLen = *ev.SessionKeyLen
	}
	return up, versionOn, micOn, keyLen
}

// flagsFor 求会话实际 flags（Version 覆盖并入——flags 是 Type 1/2/3 交集）。
func (w *ntlmWalker) flagsFor(versionOn bool) uint32 {
	f := resolveFlags(w.cfgFlags())
	if versionOn {
		f |= flagVersion
	} else {
		f &^= flagVersion
	}
	return f
}

func (w *ntlmWalker) cfgFlags() *core.NTLMFlags {
	if w.cfg == nil {
		return nil
	}
	return w.cfg.Flags
}

// ---- Generate（链驱动入口，dcerpc/dtls/kerberos 同族）----

// NTLMGenerator is the terminal-layer generator for ntlm chains.
type NTLMGenerator struct{}

func (g *NTLMGenerator) Name() string { return "ntlm" }

// GenEvents/EmitEvent mark the event-generator face（kerberos/bacnet 同款）。
func (g *NTLMGenerator) GenEvents() layers.EventGenerator { return g }
func (g *NTLMGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("ntlm generator: EmitEvent is not wired")
}

// Generate 逐会话逐事件渲染（链驱动入口）。
func (g *NTLMGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("ntlm generator: request is nil")
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("ntlm generator: EmitMsg is nil")
	}
	cfg := req.Meta.NTLM
	if cfg == nil {
		cfg = &core.NTLMConfig{}
	}
	if err := (&Planner{}).Validate(core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		NTLM:    cfg,
	}); err != nil {
		return err
	}

	host := req.Meta.DstIP
	if host == "" {
		host = "192.0.2.60"
	}
	w := newWalker(cfg, req.Meta.SrcPort, req.Meta.DstPort, host)

	// 空配置缺省基线（bacnet/dtls/kerberos 家族同款）：无 sessions 发一条最小
	// NEGOTIATE（smb2 缺省档），避免裸 {"ntlm":{}} 链静默 0 包。
	if len(cfg.Sessions) == 0 {
		sess := &core.NTLMSession{}
		ev := &core.NTLMEvent{Kind: "negotiate"}
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
				return fmt.Errorf("ntlm: sessions[%d].events[%d]: %w", si, ei, err)
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
// 走同一路径——校验即生成前置演练，不做第二套规则）。
func (w *ntlmWalker) renderSessionEvent(sess *core.NTLMSession, ev *core.NTLMEvent, si, ei int) (frame, error) {
	kind := ev.Kind
	up, versionOn, micOn, keyLen := w.resolveEvent(ev, kind)
	flags := w.flagsFor(versionOn)
	st := newSessionState(w.srcPort, w.dstPort, si)
	// 同一会话内多事件共享会话状态：重建一次（确定性派生 → 同值），
	// 但 msgID 需按事件序推进——逐事件从会话起点重放（确定性）。
	for j := 0; j < ei; j++ {
		prev := w.prevKind(sess, j)
		// request/response 共用 MessageId：每轮 down 响应后才递增
		// （既有 smb 层 BUG #5 教训：增量必须在 response 发射后）。
		if prev == "challenge" || prev == "session_setup_success" || prev == "session_setup_failure" || prev == "http_success" || prev == "http_unauthorized" {
			st.msgID++
		}
	}
	fr, err := renderEvent(kind, sess, w.cfg, flags, st, versionOn, micOn, keyLen, w.host)
	if err != nil {
		return frame{}, err
	}
	fr.up = up
	return fr, nil
}

// prevKind 返回会话内第 j 个事件的 kind（msgID 推进用）。
func (w *ntlmWalker) prevKind(sess *core.NTLMSession, j int) string {
	if j < 0 || j >= len(sess.Events) {
		return ""
	}
	return sess.Events[j].Kind
}

// init registers the generator + validator（bacnet/kerberos 同款接线）。
func init() {
	layers.RegisterLayerGenerator("ntlm", func() (layers.LayerGenerator, error) { return &NTLMGenerator{}, nil })
	layers.RegisterLayerValidator("ntlm", func(spec *core.FlowSpec) error { return (&Planner{}).Validate(*spec) })
}
