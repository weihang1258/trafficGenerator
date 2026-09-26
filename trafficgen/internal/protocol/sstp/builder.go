package sstp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// fixture 缺省（确定性，不伪造密码学语义——契约 §2 证据红线）。nonce/cert
// hash/compound MAC 的字节面是 opaque fixture：ACK 的 nonce 与 CONNECTED 的
// nonce 用同一填充，故两侧值可逐字节相等（可断言，不是随机）。
const (
	fixtureNonceFill      = 0x5A // Crypto Binding / Binding Request 的 32B nonce
	fixtureCertHashFill   = 0xC3 // 32B cert hash（SHA-256 profile）
	fixtureCompoundMAC    = 0xCA // 32B compound MAC
	fixtureStatusFill     = 0x00 // Status Info 的 AttribValue 填充
	fixturePPPInfoMinIPv4 = 20   // IPv4 头最小长度
	fixturePPPInfoMinIPv6 = 40   // IPv6 头最小长度
	fixturePPPDefaultLen  = 20   // ppp.payload_len 缺省（IPv4 头）
)

// fixtureNonce 返回 32-byte 确定性 nonce（非随机——同 fixture 同结果）。
func fixtureNonce() []byte { return fillBytes(nonceLen, fixtureNonceFill) }

func fillBytes(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// —— 属性渲染（契约 §4；MS-SSTP §2.2.5–§2.2.8）——

// buildAttribute 渲染一条属性（含 4B 属性头）。value_b64 覆盖时按该属性 ID
// 的固定/区间长度复核——0x01 必须 2B 且为 0x0001、0x03 必须 100B（SHA-256
// profile 不得截断）、0x04 必须 36B、0x02 必须落在 [8,72]。
func buildAttribute(a *core.AttributeEntry) ([]byte, error) {
	switch a.ID {
	case attrEncapsulatedProtocolID:
		val := encapsulatedProtocolIDValue()
		if a.ValueB64 != "" {
			b, err := decodeB64(a.ValueB64, "attribute value_b64")
			if err != nil {
				return nil, err
			}
			if len(b) != len(val) {
				return nil, fmt.Errorf("sstp: Encapsulated Protocol ID value must be %d bytes, got %d (attribute)", len(val), len(b))
			}
			if b[0] != 0x00 || b[1] != 0x01 {
				return nil, fmt.Errorf("sstp: Encapsulated Protocol ID value 0x%02x%02x is not PPP (0x0001) — SSTP version 1.0 supports PPP only (attribute)", b[0], b[1])
			}
			val = b
		}
		return encodeAttribute(attrEncapsulatedProtocolID, val)
	case attrStatusInfo:
		attrID := byte(0)
		if a.AttrID != nil {
			if *a.AttrID < 0 || *a.AttrID > int(attrCryptoBindingRequest) {
				return nil, fmt.Errorf("sstp: Status Info reported attribute id %d out of range 0..4 (attribute)", *a.AttrID)
			}
			attrID = byte(*a.AttrID)
		}
		status := uint32(0)
		if a.Status != nil {
			status = *a.Status
		}
		if status > sstpStatusMax {
			return nil, fmt.Errorf("sstp: Status Info status 0x%08x is not a defined ATTRIB_STATUS_* value (0x00..0x%02x) (attribute)", status, sstpStatusMax)
		}
		if a.ValueLen < 0 || a.ValueLen > sstpStatusAttribValueMax {
			return nil, fmt.Errorf("sstp: Status Info AttribValue length %d out of range 0..%d (attribute)", a.ValueLen, sstpStatusAttribValueMax)
		}
		if a.ValueB64 != "" {
			b, err := decodeB64(a.ValueB64, "attribute value_b64")
			if err != nil {
				return nil, err
			}
			if len(b) < statusInfoMinLen-attributeHeaderLen || len(b) > statusInfoMaxLen-attributeHeaderLen {
				return nil, fmt.Errorf("sstp: Status Info value %d bytes out of range %d..%d (LengthPacket = AttribValue + 12) (attribute)",
					len(b), statusInfoMinLen-attributeHeaderLen, statusInfoMaxLen-attributeHeaderLen)
			}
			return encodeAttribute(attrStatusInfo, b)
		}
		return encodeAttribute(attrStatusInfo, statusInfoValue(attrID, status, fillBytes(a.ValueLen, fixtureStatusFill)))
	case attrCryptoBinding:
		if a.ValueB64 != "" {
			b, err := decodeB64(a.ValueB64, "attribute value_b64")
			if err != nil {
				return nil, err
			}
			if len(b) != cryptoBindingLen-attributeHeaderLen {
				return nil, fmt.Errorf("sstp: Crypto Binding value must be %d bytes (LengthPacket 0x%03x), got %d (attribute)",
					cryptoBindingLen-attributeHeaderLen, cryptoBindingLen, len(b))
			}
			return encodeAttribute(attrCryptoBinding, b)
		}
		hp := byte(2) // SHA-256 profile（契约 §4）
		if a.HashProtocol != nil {
			if *a.HashProtocol != 1 && *a.HashProtocol != 2 {
				return nil, fmt.Errorf("sstp: Crypto Binding hash protocol %d is not CERT_HASH_PROTOCOL_SHA1 (1) or SHA256 (2) (attribute)", *a.HashProtocol)
			}
			hp = byte(*a.HashProtocol)
		}
		nonce, err := resolveNonce(a.NonceB64)
		if err != nil {
			return nil, err
		}
		// SHA-1 profile 用 12B Padding 补足同长（MS-SSTP §2.2.7——总长恒 104）。
		certLen, macLen := 32, 32
		if hp == 1 {
			certLen, macLen = 20, 20
		}
		val := cryptoBindingValue(hp, nonce, fillBytes(certLen, fixtureCertHashFill), fillBytes(macLen, fixtureCompoundMAC))
		if hp == 1 {
			val = append(val, fillBytes(12, 0x00)...) // Padding1（SHA-1 profile）
		}
		return encodeAttribute(attrCryptoBinding, val)
	case attrCryptoBindingRequest:
		if a.ValueB64 != "" {
			b, err := decodeB64(a.ValueB64, "attribute value_b64")
			if err != nil {
				return nil, err
			}
			if len(b) != cryptoBindingRequestLen-attributeHeaderLen {
				return nil, fmt.Errorf("sstp: Crypto Binding Request value must be %d bytes (LengthPacket 0x%03x), got %d (attribute)",
					cryptoBindingRequestLen-attributeHeaderLen, cryptoBindingRequestLen, len(b))
			}
			return encodeAttribute(attrCryptoBindingRequest, b)
		}
		bitmask := byte(0x02) // SHA-256 only
		if a.HashBitmask != nil {
			if *a.HashBitmask < 1 || *a.HashBitmask > 3 {
				return nil, fmt.Errorf("sstp: Crypto Binding Request hash bitmask 0x%02x must select at least one of SHA1(bit0)/SHA256(bit1) (attribute)", *a.HashBitmask)
			}
			bitmask = byte(*a.HashBitmask)
		}
		nonce, err := resolveNonce(a.NonceB64)
		if err != nil {
			return nil, err
		}
		return encodeAttribute(attrCryptoBindingRequest, cryptoBindingRequestValue(bitmask, nonce))
	default:
		// 未知 Attribute ID（含把 Message Type 0x0005/0x0006 当作属性 ID 的形状
		// ——契约 §11 第 16 行点名）。
		return nil, fmt.Errorf("sstp: attribute id 0x%02x is not a defined Attribute ID (0x01..0x04); message types 0x0005/0x0006 are Message Type values, not attribute ids (attribute)", a.ID)
	}
}

func decodeB64(s, what string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("sstp: %s is not valid base64: %v", what, err)
	}
	return b, nil
}

func resolveNonce(nonceB64 string) ([]byte, error) {
	if nonceB64 == "" {
		return fixtureNonce(), nil
	}
	b, err := decodeB64(nonceB64, "attribute nonce_b64")
	if err != nil {
		return nil, err
	}
	if len(b) != nonceLen {
		return nil, fmt.Errorf("sstp: nonce must be %d bytes, got %d (attribute)", nonceLen, len(b))
	}
	return b, nil
}

// sstpStatusMax / sstpStatusAttribValueMax：MS-SSTP §2.2.8 的枚举上界与
// AttribValue 上限（64）。
const (
	sstpStatusMax           = 0x0b
	sstpStatusAttribValueMax = 64
)

// —— 控制消息渲染 ——

// buildControl 渲染一条控制消息：属性和恒定 Length（覆盖整包，含 4B common
// header 与 2+2 控制字段）。
func buildControl(e *core.SSTPEvent) ([]byte, error) {
	kt, ok := kindTable[e.Kind]
	if !ok || !kt.control {
		return nil, fmt.Errorf("sstp: unknown control message kind %q (header)", e.Kind)
	}
	// C bit↔Message Type 一致性（契约 §17 错误分支②）：控制包不带 PPP data
	// ——ppp 字段只属于 C=0 数据包。
	if e.PPP != nil {
		return nil, fmt.Errorf("sstp: kind %q is a control message (C=1) but carries a ppp payload — PPP frames ride C=0 data packets only (C bit)", e.Kind)
	}
	attrs := make([][]byte, 0, len(e.Attributes))
	for i := range e.Attributes {
		a, err := buildAttribute(&e.Attributes[i])
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, a)
	}
	return encodeControlPacket(kt.msgType, attrs)
}

// —— PPP data 渲染（契约 §7；RFC 1661 / RFC 3078）——

// buildPPP 渲染 C=0 数据包的 PPP 帧：ff 03 | Protocol(2) | Information。
// MPPE（RFC 3078）只换 protocol 字段与 information 的表示，不改变帧结构、
// SSTP Length 或地址族语义边界（契约 §7）。
func buildPPP(e *core.SSTPEvent) ([]byte, error) {
	p := e.PPP
	if p == nil {
		return nil, fmt.Errorf("sstp: kind %q requires a ppp block (C=0 data packet carries a PPP frame) (ppp)", e.Kind)
	}
	if len(e.Attributes) > 0 {
		return nil, fmt.Errorf("sstp: kind %q is a C=0 data packet but carries %d attributes — attributes belong to control messages (C bit)", e.Kind, len(e.Attributes))
	}
	switch p.Framing {
	case "", "uncompressed":
		// 契约 §7 正例固定 ff 03；压缩形未在本版 profile 内。
	default:
		return nil, fmt.Errorf("sstp: ppp framing %q is not the uncompressed profile (ff 03 + protocol) — compressed framing must be declared as its own profile and is not produced in this version (framing)", p.Framing)
	}
	proto, err := pppProtocolFor(p)
	if err != nil {
		return nil, err
	}
	info, err := pppInformation(p)
	if err != nil {
		return nil, err
	}
	return encodePPPFrame(proto, info), nil
}

func pppProtocolFor(p *core.PPPEntry) (uint16, error) {
	if p.MPPE {
		// MPPE 加密的 information 用压缩加密数据报协议号（RFC 3078 §2）；
		// 载荷不可解，不把密文解释为 IPv4/IPv6（契约 §7 证据红线）。
		return pppProtocolMPPE, nil
	}
	switch p.Protocol {
	case "ipv4":
		return pppProtocolIPv4, nil
	case "ipv6":
		return pppProtocolIPv6, nil
	default:
		return 0, fmt.Errorf("sstp: ppp protocol %q is not ipv4/ipv6 (PPP protocol field is declared, never derived from the outer IP family) (ppp)", p.Protocol)
	}
}

// pppInformation 产出 PPP information：payload_b64 显式字节（按声明协议族
// 复核版本半字节）或按 payload_len 合成的最小 IP 报文。
func pppInformation(p *core.PPPEntry) ([]byte, error) {
	want := byte(4)
	minLen := fixturePPPInfoMinIPv4
	if p.Protocol == "ipv6" {
		want = 6
		minLen = fixturePPPInfoMinIPv6
	}
	if p.PayloadB64 != "" {
		b, err := decodeB64(p.PayloadB64, "ppp payload_b64")
		if err != nil {
			return nil, err
		}
		if len(b) > 0 && b[0]>>4 != want {
			return nil, fmt.Errorf("sstp: ppp payload version nibble 0x%x does not match declared protocol %q (IPv4/IPv6 mismatch) (ppp)", b[0]>>4, p.Protocol)
		}
		return b, nil
	}
	length := p.PayloadLen
	if length == 0 {
		length = fixturePPPDefaultLen
		if p.Protocol == "ipv6" {
			length = fixturePPPInfoMinIPv6
		}
	}
	if p.MPPE {
		// MPPE：information 是 opaque 密文，长度由 fixture 钉（block 对齐
		// /跨边界两种形态在 #10），不做 IP 头结构约束。
		if length <= 0 {
			return nil, fmt.Errorf("sstp: mppe information length %d must be positive (ppp)", length)
		}
		return fillBytes(length, fixtureNonceFill), nil
	}
	if length < minLen {
		return nil, fmt.Errorf("sstp: ppp payload_len %d is shorter than the %d-byte %s header (ppp)", length, minLen, p.Protocol)
	}
	if p.Protocol == "ipv6" {
		return synthIPv6Payload(length), nil
	}
	return synthIPv4Payload(length), nil
}

// synthIPv4Payload 合成以 10.0.0.1 → 10.0.0.2 为端点、protocol=1(ICMP) 的
// 最小 IPv4 报文（头 20B + 零填充），头校验和按 RFC 1071 实算（#8 断言
// IPv4 version/length/checksum 的字节面）。
func synthIPv4Payload(length int) []byte {
	out := make([]byte, length)
	out[0] = 0x45 // Version 4 + IHL 5
	binary.BigEndian.PutUint16(out[2:4], uint16(length))
	out[8] = 64        // TTL
	out[9] = 1         // Protocol = ICMP
	copy(out[12:16], []byte{10, 0, 0, 1})
	copy(out[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(out[10:12], core.EncapIPv4HeaderChecksum(out[:20]))
	return out
}

// synthIPv6Payload 合成 2001:db8::1 → 2001:db8::2、Next Header=59（No Next
// Header）的最小 IPv6 报文（头 40B + 零填充）。
func synthIPv6Payload(length int) []byte {
	out := make([]byte, length)
	out[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(out[4:6], uint16(length-fixturePPPInfoMinIPv6))
	out[6] = 59 // Next Header = No Next Header
	out[7] = 64 // Hop Limit
	copy(out[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(out[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	return out
}

// —— 会话状态机（单权威；契约 §6）——

// 会话状态：TLS established → REQUEST → ACK/NAK → CONNECTED → PPP data →
//（可选）ABORT/DISCONNECT → close。NAK 是拒绝路径：不能继续 CONNECTED 或
// PPP data；ABORT 之后不得继续该 connection 的控制或 PPP data（契约 §6）。
const (
	stateStart        = "start"
	stateRequested    = "requested"    // REQUEST 已发，等 ACK/NAK
	stateAcked        = "acked"        // ACK 已收，等 CONNECTED
	stateEstablished  = "established"  // CONNECTED 已发，PPP data 允许
	stateRejected     = "rejected"     // NAK：连接终止
	stateAborted      = "aborted"      // ABORT：连接终止
	stateDisconnected = "disconnected" // DISCONNECT 对：连接终止
)

// sstpWalker 是会话状态的唯一权威（校验与生成走同一路径——不是第二套规则）。
type sstpWalker struct{ state string }

func newWalker() *sstpWalker { return &sstpWalker{state: stateStart} }

// step 推进一个事务：状态合法性 + 方向合法性 + 必带属性。
func (w *sstpWalker) step(e *core.SSTPEvent) error {
	// kind 未知走 header 锚词（控制头的 Message Type 字段域；契约 §14.2
	// "未知 Type 走 header/length 拒"）。
	kt, ok := kindTable[e.Kind]
	if !ok {
		return fmt.Errorf("sstp: unknown message kind %q in the control header (message type is one of 0x0001..0x0009, or ppp_data for C=0) (header)", e.Kind)
	}
	if _, err := w.direction(e); err != nil {
		return err
	}
	terminal := func() error {
		return fmt.Errorf("sstp: %s is not allowed after the connection reached state %q (state)", e.Kind, w.state)
	}
	switch {
	case !kt.control:
		// C=0 PPP data：仅 CONNECTED 之后（越序 → #17）。
		if w.state != stateEstablished {
			return terminal()
		}
		return nil
	case e.Kind == "call_connect_request":
		if w.state != stateStart {
			return terminal()
		}
		if err := requireAttr(e, attrEncapsulatedProtocolID, "CALL CONNECT REQUEST", "Encapsulated Protocol ID"); err != nil {
			return err
		}
		w.state = stateRequested
	case e.Kind == "call_connect_ack":
		if w.state != stateRequested {
			return terminal()
		}
		if err := requireAttr(e, attrCryptoBindingRequest, "CALL CONNECT ACK", "Crypto Binding Request"); err != nil {
			return err
		}
		w.state = stateAcked
	case e.Kind == "call_connect_nak":
		if w.state != stateRequested {
			return terminal()
		}
		if err := requireAttr(e, attrStatusInfo, "CALL CONNECT NAK", "Status Info"); err != nil {
			return err
		}
		w.state = stateRejected
	case e.Kind == "call_connected":
		if w.state != stateAcked {
			return terminal()
		}
		if err := requireAttr(e, attrCryptoBinding, "CALL CONNECTED", "Crypto Binding"); err != nil {
			return err
		}
		w.state = stateEstablished
	case e.Kind == "echo_request", e.Kind == "echo_response":
		// 保活只在 CONNECTED 后（契约 §14.2 不适用格）。
		if w.state != stateEstablished {
			return terminal()
		}
	case e.Kind == "call_disconnect":
		if w.state != stateEstablished {
			return terminal()
		}
		w.state = stateDisconnected
	case e.Kind == "call_disconnect_ack":
		if w.state != stateDisconnected {
			return terminal()
		}
	case e.Kind == "call_abort":
		// ABORT 在合法控制阶段由任一方向发送（契约 §6/#5）。
		if w.state != stateRequested && w.state != stateAcked && w.state != stateEstablished {
			return terminal()
		}
		w.state = stateAborted
	default:
		// 未知 kind：walkSession 的入口门已先行 header 锚词拒——此处是直接
		// 调用 step() 的防御分支（同一文案，单真相）。
		return fmt.Errorf("sstp: unknown message kind %q in the control header (message type is one of 0x0001..0x0009, or ppp_data for C=0) (header)", e.Kind)
	}
	return nil
}

// direction 解析并校验事务方向：c2s = client→server（Up=true）。有唯一合法
// 方向的控制消息（REQUEST/ACK/NAK/CONNECTED/DISCONNECT 对）允许缺省派生；
// 任一方向可发的消息（PPP data/ECHO/ABORT）必须显式声明方向。
func (w *sstpWalker) direction(e *core.SSTPEvent) (bool, error) {
	declared := e.Direction
	if declared != "" && declared != "c2s" && declared != "s2c" {
		return false, fmt.Errorf("sstp: kind %q direction %q must be c2s or s2c (direction)", e.Kind, declared)
	}
	canonical := ""
	switch e.Kind {
	case "call_connect_request", "call_connected", "call_disconnect":
		canonical = "c2s"
	case "call_connect_ack", "call_connect_nak", "call_disconnect_ack":
		canonical = "s2c"
	}
	if canonical != "" {
		if declared == "" {
			return canonical == "c2s", nil
		}
		if declared != canonical {
			return false, fmt.Errorf("sstp: kind %q must be sent %s (MS-SSTP §2.2), got %q (direction)", e.Kind, canonical, declared)
		}
		return canonical == "c2s", nil
	}
	if declared == "" {
		return false, fmt.Errorf("sstp: kind %q may be sent by either peer — direction must be declared explicitly (c2s/s2c) (direction)", e.Kind)
	}
	return declared == "c2s", nil
}

// dirName 把方向布尔渲染成 c2s/s2c（错误文案用；Up=true 即 c2s）。
func dirName(up bool) string {
	if up {
		return "c2s"
	}
	return "s2c"
}

// requireAttr 断言控制消息必带的属性（MS-SSTP §2.2.9–§2.2.11 的 MUST）。
func requireAttr(e *core.SSTPEvent, id int, msg, name string) error {
	for i := range e.Attributes {
		if e.Attributes[i].ID == id {
			return nil
		}
	}
	return fmt.Errorf("sstp: %s requires the %s attribute (id 0x%02x) (attribute)", msg, name, id)
}

// expectNext maps a transaction's declared 成功分支 to the kinds that satisfy
// it（契约 §16.3 五件套：每事务写清成功分支/失败分支）。
var expectNext = map[string][]string{
	"ack":            {"call_connect_ack"},
	"nak":            {"call_connect_nak"},
	"connected":      {"call_connected"},
	"ppp":            {"ppp_data"},
	"echo":           {"echo_request", "echo_response"},
	"abort":          {"call_abort"},
	"disconnect":     {"call_disconnect", "call_disconnect_ack"},
	"disconnect_ack": {"call_disconnect_ack"},
}

// walkSession 走一个会话的全部事务：状态机 + 成功分支声明（expect）与实际
// 下一条事务的一致性。返回每事务的方向与字节。
func walkSession(sess *core.SSTPSession, si int) ([]bool, [][]byte, error) {
	where := func(ti int) string {
		id := sess.Transactions[ti].ID
		if id == "" {
			id = fmt.Sprintf("#%d", ti+1)
		}
		sid := sess.ID
		if sid == "" {
			sid = fmt.Sprintf("#%d", si+1)
		}
		return fmt.Sprintf("sstp: session %s transaction %s", sid, id)
	}
	w := newWalker()
	ups := make([]bool, 0, len(sess.Transactions))
	msgs := make([][]byte, 0, len(sess.Transactions))
	for ti := range sess.Transactions {
		e := &sess.Transactions[ti]
		// kind 先行：未知 kind 走 header 锚词——direction 的"任一方向须显式
		// 声明"判死只针对已知 kind（契约 §14.2"未知 Type 走 header/length 拒"）。
		if _, known := kindTable[e.Kind]; !known {
			return nil, nil, fmt.Errorf("%s: sstp: unknown message kind %q in the control header (message type is one of 0x0001..0x0009, or ppp_data for C=0) (header)", where(ti), e.Kind)
		}
		up, err := w.direction(e)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", where(ti), err)
		}
		if err := w.step(e); err != nil {
			return nil, nil, fmt.Errorf("%s: %v", where(ti), err)
		}
		var msg []byte
		if kt := kindTable[e.Kind]; kt.control {
			msg, err = buildControl(e)
		} else {
			// C=0 数据包 = 4-byte common header（C=0）+ PPP frame：S+4 即
			// `ff 03`（契约 §3 表 + RFC 1661）——PPP 帧必须包在 data 包里，
			// 不裸发帧字节（否则线上缺 Version/C/Length）。
			var frame []byte
			frame, err = buildPPP(e)
			if err == nil {
				msg, err = encodeDataPacket(frame)
			}
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", where(ti), err)
		}
		if e.Group < 0 || e.Chunk < 0 {
			return nil, nil, fmt.Errorf("%s: chunk/group must not be negative (framing)", where(ti))
		}
		// group 声明的前置检查必须在**校验面**（walkSession 被 validateSpec
		// 复用）：生成期的同类守卫会被 drive 吞成空流/截断流（"驱动失败→空流"
		// 契约），配置结构错必须同步报错、零假成功。
		// 语义：group=N 写在**组首**事务上（"本条与后续 N-1 条同进一条
		// record"）；组成员不得自带 group（嵌套组无定义）。
		if e.Group > 1 {
			// 组必须凑满（少一条 = 声明与实际不一致，拒而不是静默合并）。
			if ti+e.Group > len(sess.Transactions) {
				return nil, nil, fmt.Errorf("%s: group=%d needs %d messages but only %d remain in the session (framing)", where(ti), e.Group, e.Group, len(sess.Transactions)-ti)
			}
			// 同组必须同方向（TLS record 单向：跨方向合并无法表达为一条 record）。
			for k := 1; k < e.Group; k++ {
				member := &sess.Transactions[ti+k]
				if member.Group > 1 {
					return nil, nil, fmt.Errorf("%s: group=%d member %q declares its own group — nested groups are undefined (framing)", where(ti), e.Group, member.Kind)
				}
				nextUp, err := w.direction(member)
				if err != nil {
					return nil, nil, fmt.Errorf("%s: %v", where(ti), err)
				}
				if nextUp != up {
					return nil, nil, fmt.Errorf("%s: grouped messages must share one direction — a TLS record is unidirectional (%s vs %s) (boundary)", where(ti), dirName(up), dirName(nextUp))
				}
			}
		}
		if e.Expect != "" {
			want, ok := expectNext[e.Expect]
			if !ok {
				return nil, nil, fmt.Errorf("%s: expect %q is not a declared success branch (ack/nak/connected/ppp/echo/abort/disconnect) (sequence)", where(ti), e.Expect)
			}
			if ti+1 >= len(sess.Transactions) {
				return nil, nil, fmt.Errorf("%s: expect %q declared but the session ends here — a declared success branch needs its reply (sequence)", where(ti), e.Expect)
			}
			next := sess.Transactions[ti+1].Kind
			matched := false
			for _, k := range want {
				if k == next {
					matched = true
					break
				}
			}
			if !matched {
				return nil, nil, fmt.Errorf("%s: expect %q but the next transaction is %q (state/sequence)", where(ti), e.Expect, next)
			}
		}
		ups = append(ups, up)
		msgs = append(msgs, msg)
	}
	return ups, msgs, nil
}

// —— 生成器 ——

// SSTPGenerator is the terminal-layer generator for sstp chains.
type SSTPGenerator struct{}

// Name returns "sstp".
func (g *SSTPGenerator) Name() string { return "sstp" }

// GenEvents/EmitEvent mark the event-generator face（kerberos/bacnet 同款）。
func (g *SSTPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is unused: the chain drives Generate directly (终结层事件经
// EmitMsg 流出，不经 EmitEvent 回流)。
func (g *SSTPGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("sstp generator: EmitEvent is not wired")
}

// Generate renders the configured sessions' SSTP messages and emits them as
// application-data payload events（tls 层包 record、tcp 层成段）。
//
// 流式：逐事务渲染直发 EmitMsg，无全量聚合；group 缓冲上限 = 该组事务数
// （fixture 尺寸），chunk 只按当前 message 切分。
func (g *SSTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("sstp generator: request is nil")
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("sstp generator: EmitMsg is nil")
	}
	cfg := req.Meta.SSTP
	if cfg == nil {
		cfg = &core.SSTPConfig{}
	}
	if err := validateSpec(cfg); err != nil {
		return err
	}
	if err := resolveCarrier(req.Chain); err != nil {
		return err
	}
	sessions := resolveSessions(cfg)

	emit := func(up bool, buf []byte) error {
		if len(buf) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(layers.MessageEvent{Up: up, Bytes: buf})
	}

	// 空配置基线（bacnet/dtls/kerberos 家族同款）：裸 {"sstp":{}} 发一条最小
	// CALL CONNECT REQUEST（14B = 8B 控制固定部 + 6B Encapsulated Protocol ID），
	// 不静默 0 包。
	if len(sessions) == 0 {
		base := core.SSTPEvent{Kind: "call_connect_request", Attributes: []core.AttributeEntry{{ID: attrEncapsulatedProtocolID}}}
		msg, err := buildControl(&base)
		if err != nil {
			return err
		}
		return emit(true, msg)
	}

	for si := range sessions {
		ups, msgs, err := walkSession(&sessions[si], si)
		if err != nil {
			return err
		}
		// 分会话逐事务发射：group 合并同方向相邻 message 进一条 record，
		// chunk 把发射缓冲切成 ≤chunk 字节的多条 record（契约 §5/§8：
		// record 边界 ≠ message 边界，双侧都要能表达）。
		var pend []byte
		var pendUp bool
		var pendChunk int
		flush := func() error {
			if len(pend) == 0 {
				return nil
			}
			buf, chunk, up := pend, pendChunk, pendUp
			pend, pendChunk = nil, 0
			if chunk <= 0 {
				return emit(up, buf)
			}
			for len(buf) > 0 {
				n := len(buf)
				if n > chunk {
					n = chunk
				}
				if err := emit(up, buf[:n]); err != nil {
					return err
				}
				buf = buf[n:]
			}
			return nil
		}
		groupLeft := 0 // 当前组剩余待并入的 message 数（组首声明 group=N → N-1）
		for ti := range msgs {
			e := &sessions[si].Transactions[ti]
			if groupLeft > 0 {
				// 组成员（方向/存在性已由 walkSession 校验）并入同一条 record。
				pend, pendUp = append(pend, msgs[ti]...), ups[ti]
				groupLeft--
				if groupLeft == 0 {
					if err := flush(); err != nil {
						return err
					}
				}
				continue
			}
			// 新事务：先冲掉任何挂起缓冲（组首/普通事务都不与前一条合并）。
			if err := flush(); err != nil {
				return err
			}
			pend, pendUp, pendChunk = msgs[ti], ups[ti], e.Chunk
			if e.Group > 1 {
				groupLeft = e.Group - 1
				continue
			}
			if err := flush(); err != nil {
				return err
			}
		}
		if err := flush(); err != nil {
			return err
		}
	}
	return nil
}

// resolveSessions 归一化配置的两种会话形状：sessions[] 优先；仅 events[] 时
// 视作单会话 s1（契约 §2 键表两种写法；两处并存且都非空 = 双权威，拒）。
func resolveSessions(cfg *core.SSTPConfig) []core.SSTPSession {
	if len(cfg.Sessions) > 0 {
		return cfg.Sessions
	}
	if len(cfg.Events) > 0 {
		return []core.SSTPSession{{ID: "s1", TLSSession: "tls-1", Transactions: cfg.Events}}
	}
	return nil
}
