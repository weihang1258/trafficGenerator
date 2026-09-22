// Package hl7 planner: negative-path validation (33 wire_fault kinds per
// design §6/§7 — v2.1.1 契约枚举名) plus structural config checks. Every
// rejected spec must surface as a task error — never a completed/0-packet or
// TCP-shell fake success.
//
// D-HL7-1 裁定4/裁定9：负例不走"见字符串即拒"自证循环——33 值逐值裁定自然面
// 守卫（20 值，validator 在自然配置上执法同一故障）与书面豁免（13 值，builder
// 恒产合法线格式/生成器不变式，注入通道唯一入口），处置表挂 D-HL7-1。
package hl7

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// wireFaultAnchors maps each wire_fault kind to its error_contains anchor
// (契约 §7 表主锚词——枚举名与锚词均以 68-hl7-design v2.1.1 为准；B6 旧名
// mllp_*/carrier_tcp_missing 系 v2.1 改名前值，不沿用).
var wireFaultAnchors = map[string]string{
	// framing
	"framing_sob_missing":   "mllp",
	"framing_eob_missing":   "mllp",
	"framing_eob_malformed": "mllp",
	"framing_control_byte":  "mllp",
	// segment structure
	"segment_first_not_msh": "msh",
	"segment_no_cr":         "segment",
	"segment_after_eob":     "segment",
	"segment_name_invalid":  "segment",
	// separator / field
	"msh1_invalid":       "separator",
	"msh2_invalid":       "separator",
	"separator_mismatch": "separator",
	"escape_invalid":     "escape",
	// msh required
	"msh9_missing":  "msh",
	"msh10_missing": "msh",
	"msh11_missing": "msh",
	"msh12_missing": "msh",
	"msh9_domain":   "msh",
	// ack correlation
	"ack_msa2_mismatch": "ack",
	"ack_no_msh9":       "ack",
	"ack_no_msa":        "ack",
	"ack_code_invalid":  "ack",
	// carrier
	"carrier_udp":    "carrier",
	"carrier_no_tcp": "layer",
	"port_invalid":   "port",
	// length
	"len_msh9":  "length",
	"len_msh10": "length",
	"len_msh12": "length",
	"len_msh7":  "length",
	"len_msa2":  "length",
	// semantic
	"event_mismatch":           "event",
	"address_family_mixed":     "address",
	"required_segment_missing": "segment",
	"z_segment_unconfigured":   "z",
}

// knownSegmentNames is the contract §6 段表白名单（∪ 显式 Z 段）。
var knownSegmentNames = map[string]bool{
	"MSH": true, "EVN": true, "PID": true, "PV1": true, "OBR": true,
	"OBX": true, "SCH": true, "AIS": true, "MSA": true, "ERR": true,
}

// knownMessageCodes is the MSH-9 message-code domain (契约 §3.4 现网常用
// + B6 集合；负例 msh9_domain 的 XYZ 即不在其内).
var knownMessageCodes = map[string]bool{
	"ADT": true, "ORU": true, "SIU": true, "ACK": true,
	"ORM": true, "MDM": true, "DFT": true,
}

// requiredSegmentsByStructure is the D-6 必需业务段集（契约 §6 Validate 行
// 显式声明）：key = MSH-9 结构标识（message_type 第三组件）。
var requiredSegmentsByStructure = map[string][]string{
	"ADT_A01": {"EVN", "PID", "PV1"},
	"ADT_A02": {"EVN", "PID", "PV1"},
	"ADT_A03": {"EVN", "PID", "PV1"},
	"ORU_R01": {"OBR"},
	"SIU_S12": {"SCH", "AIS"},
}

// Validate runs all hl7 config validation. nil cfg = empty default stream.
func Validate(spec core.FlowSpec) error {
	cfg := spec.HL7
	if cfg == nil {
		// empty config default flow: P0b baseline
		return nil
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	for si, sess := range cfg.Sessions {
		if err := validateSession(cfg, sess, si); err != nil {
			return err
		}
	}
	return nil
}

func validateConfig(cfg *core.HL7Config) error {
	// profile check
	if cfg.Profile != "" && cfg.Profile != "mllp" {
		return fmt.Errorf("hl7: profile %q is not supported (only mllp)", cfg.Profile)
	}
	// version check
	if cfg.Version != "" {
		switch cfg.Version {
		case "2.3", "2.4", "2.5", "2.8":
		default:
			return fmt.Errorf("hl7: version %q is not supported (2.3/2.4/2.5/2.8)", cfg.Version)
		}
	}
	// field separator: must be 1 char（msh1_invalid 自然面守卫）
	if cfg.FieldSeparator != "" && len(cfg.FieldSeparator) != 1 {
		return fmt.Errorf("hl7: field_separator must be 1 character (got %d) (separator)", len(cfg.FieldSeparator))
	}
	// encoding chars: must be 4 chars（msh2_invalid 自然面守卫）
	if cfg.EncodingChars != "" && len(cfg.EncodingChars) != 4 {
		return fmt.Errorf("hl7: encoding_chars must be 4 characters (got %d) (separator)", len(cfg.EncodingChars))
	}
	// ack mode check
	if cfg.AckMode != "" && cfg.AckMode != "auto" && cfg.AckMode != "null" {
		if !isValidAckCodeOrObject(cfg.AckMode) {
			return fmt.Errorf("hl7: ack_mode %q not supported (auto/null/AA/AE/AR or {code:..}) (ack)", cfg.AckMode)
		}
	}
	// wire_fault check: known kind → reject with its §7 primary anchor
	// (注入通道唯一入口；自然面守卫见各 validate* 函数).
	if cfg.WireFault != "" {
		anchor, ok := wireFaultAnchors[cfg.WireFault]
		if !ok {
			return fmt.Errorf("hl7: wire_fault %q is not a known negative-path kind", cfg.WireFault)
		}
		return fmt.Errorf("hl7: wire fault %q injected (%s)", cfg.WireFault, anchor)
	}
	return nil
}

func validateSession(cfg *core.HL7Config, sess core.HL7Session, si int) error {
	if len(sess.Events) == 0 {
		return fmt.Errorf("hl7: session[%d] has no events", si)
	}
	// 会话 ack_mode 值域（ack_code_invalid 自然面：显式码 ∉ AA/AE/AR）。
	if sess.AckMode != "" && sess.AckMode != "auto" && sess.AckMode != "null" && !isValidAckCodeOrObject(sess.AckMode) {
		return fmt.Errorf("hl7: session[%d] ack_mode %q invalid (auto/null/AA/AE/AR) (ack)", si, sess.AckMode)
	}
	// 契约 §6 动态值：会话级策略对象解析（未知 strategy/坏 range 即拒——
	// 静默忽略未知键即 F11 级故障面）。
	where := fmt.Sprintf("hl7: session[%d]", si)
	st, err := newDynState(&sess, where)
	if err != nil {
		return err
	}
	// D-HL7-1 裁定9①：控制 ID 判重在解析后集合上——显式钉值、会话级
	// 策略值与 MSG%04d 运行期分配同一空间（megaco U1 教训前置；resolve
	// 为唯一解析权威，与生成器逐事件同序同值）。
	seenCtrl := map[string]bool{}
	for ei := range sess.Events {
		_, ctrlID, _ := st.resolve(&sess.Events[ei], "")
		if len(ctrlID) > 20 {
			return fmt.Errorf("%s event[%d] resolved control id %q exceeds 20-char MSH-10 bound (length)", where, ei, ctrlID)
		}
		if seenCtrl[ctrlID] {
			return fmt.Errorf("%s event[%d] duplicate control id %q within the session scope (msh)", where, ei, ctrlID)
		}
		seenCtrl[ctrlID] = true
	}
	// framing_control_byte 自然面（终审 F3）：会话级 MSH 承载字段同扫
	//（sending/receiving app/fac 上线入 MSH-3..6；Name 经 @name 可落线）。
	for _, s := range []string{sess.SendingApp, sess.SendingFac, sess.ReceivingApp, sess.ReceivingFac, sess.Name} {
		if strings.ContainsAny(s, "\x0b\x1c") {
			return fmt.Errorf("%s carries an unescaped MLLP control byte in an MSH-bound field (escape or remove it) (mllp)", where)
		}
	}
	for ei := range sess.Events {
		if err := validateEvent(cfg, sess, st, &sess.Events[ei], si, ei); err != nil {
			return err
		}
	}
	return nil
}

func validateEvent(cfg *core.HL7Config, sess core.HL7Session, st *dynState, ev *core.HL7Event, si, ei int) error {
	where := fmt.Sprintf("hl7: session[%d].event[%d]", si, ei)
	// direction check
	if ev.Direction != "" && ev.Direction != "c2s" && ev.Direction != "s2c" {
		return fmt.Errorf("%s direction %q invalid (c2s/s2c)", where, ev.Direction)
	}
	// kind check
	if ev.Kind != "" && ev.Kind != "msg" {
		return fmt.Errorf("%s kind %q invalid (msg)", where, ev.Kind)
	}
	// framing_control_byte 自然面（终审 F3）：事件级 MSH 承载键全扫
	//（message_type/control_id/timestamp/msh8_security/msa3_text——此前
	// 只扫 segments 字段，MSH-10 槽位 0x0B 实证落线）。
	for i, s := range []string{ev.MessageType, ev.ControlID, ev.Timestamp, ev.MSH8Security, ev.MSA3Text} {
		if strings.ContainsAny(s, "\x0b\x1c") {
			return fmt.Errorf("%s MSH-bound field[%d] carries an unescaped MLLP control byte (escape or remove it) (mllp)", where, i)
		}
	}
	// msh9_missing 自然面：message_type 必填（builder 由它渲染 MSH-9；
	// 空值 = MSH-9 缺失故障的自然表达）。
	if ev.MessageType == "" {
		return fmt.Errorf("%s message_type required (renders MSH-9 code^event^structure) (msh)", where)
	}
	if err := validateMessageType(ev.MessageType); err != nil {
		return fmt.Errorf("%s: %v", where, err)
	}
	// len_msh9 自然面（设计 §8 MSH-9 ≤15 字符；恰等上界合法）。
	if len(ev.MessageType) > 15 {
		return fmt.Errorf("%s message_type length %d exceeds 15-char MSH-9 bound (length)", where, len(ev.MessageType))
	}
	// len_msh10 自然面（MSH-10 ≤20；显式钉值越界即拒）。
	if len(ev.ControlID) > 20 {
		return fmt.Errorf("%s control_id length %d exceeds 20-char MSH-10 bound (length)", where, len(ev.ControlID))
	}
	// len_msh12 自然面（事件级 version 为原文字符串，≤60）。
	if len(ev.Version) > 60 {
		return fmt.Errorf("%s version length %d exceeds 60-char MSH-12 bound (length)", where, len(ev.Version))
	}
	// len_msh7 自然面（MSH-7 ≤26 textual 上界；时间戳钉值越界即拒）。
	if len(ev.Timestamp) > 26 {
		return fmt.Errorf("%s timestamp length %d exceeds 26-char MSH-7 bound (length)", where, len(ev.Timestamp))
	}
	// ack 配对面（事件级 ack 值域；ack_code_invalid 自然面）。
	if ev.Ack != "" && ev.Ack != "auto" && ev.Ack != "null" && !isValidAckCodeOrObject(ev.Ack) {
		return fmt.Errorf("%s ack %q invalid (auto/null/AA/AE/AR or {code:..}) (ack)", where, ev.Ack)
	}
	// wire_fault injection: known kind → reject with anchor.
	if ev.WireFault != "" {
		anchor, ok := wireFaultAnchors[ev.WireFault]
		if !ok {
			return fmt.Errorf("%s wire_fault %q not a known kind", where, ev.WireFault)
		}
		return fmt.Errorf("%s wire fault %q injected (%s)", where, ev.WireFault, anchor)
	}
	// segment checks
	eventParts := strings.Split(ev.MessageType, "^")
	for sgi := range ev.Segments {
		if err := validateSegCommon(st, ev, &ev.Segments[sgi], where, sgi); err != nil {
			return err
		}
	}
	// 终审 F2：err_segments 过同一段门（段名表/Z 门/控制字节/转义/占位符）
	// + len_msa2 自然面守卫（err_segments MSA-2 >20 即拒——处置表该值由
	// 豁免行改判自然面守卫行：派生 MSA 传递论证只覆盖派生面，不覆盖此
	// 自然面）。校验对象 = 实际渲染的两个来源：resolve 后 ack spec 内嵌
	// err_segments（对象/字符串形，经 UnmarshalJSON 收敛为规范串）+ 事件级
	// 结构体 ErrSegments。resolveAckSpec 与生成器同函数同优先级。
	_, ackErrSegs := parseAckSpec(resolveAckSpec(cfg, sess, *ev))
	errSegs := make([]core.HL7Segment, 0, len(ackErrSegs)+len(ev.ErrSegments))
	errSegs = append(errSegs, ackErrSegs...)
	errSegs = append(errSegs, ev.ErrSegments...)
	for sgi := range errSegs {
		if err := validateSegCommon(st, ev, &errSegs[sgi], where, sgi); err != nil {
			return err
		}
		if seg := errSegs[sgi]; seg.Name == "MSA" && len(seg.Fields) > 1 {
			if sv, ok := seg.Fields[1].(string); ok && len(sv) > 20 {
				return fmt.Errorf("%s err_segments[%d] MSA-2 length %d exceeds 20-char MSA-2 bound (length)", where, sgi, len(sv))
			}
		}
	}
	// event_mismatch 自然面：EVN-1 与 MSH-9 触发事件一致（C-13）。
	if len(eventParts) >= 2 {
		for _, seg := range ev.Segments {
			if seg.Name == "EVN" && len(seg.Fields) > 0 {
				if v, ok := seg.Fields[0].(string); ok && v != "" && v != eventParts[1] {
					return fmt.Errorf("%s EVN-1 %q does not match MSH-9 trigger event %q (event)", where, v, eventParts[1])
				}
			}
		}
	}
	// required_segment_missing 自然面：按 MSH-9 结构声明的必需业务段集
	//（D-6：ADT^A01/A02/A03 必需 EVN+PID+PV1、ORU^R01 必需 OBR、
	// SIU^S12 必需 SCH+AIS；缺失拒绝）。
	if len(eventParts) >= 3 {
		if req, ok := requiredSegmentsByStructure[eventParts[2]]; ok {
			have := map[string]bool{}
			for _, seg := range ev.Segments {
				have[seg.Name] = true
			}
			for _, name := range req {
				if !have[name] {
					return fmt.Errorf("%s structure %s requires segment %s which is missing (segment)", where, eventParts[2], name)
				}
			}
		}
	}
	return nil
}

// validateSegCommon is the shared per-segment gate (终审 F2：请求段与
// err_segments 一处一面)——MSH 拒（终审 F7：MSH 由 message_type/会话字段
// 自动前置，用户自携即双渲染）、段名表/Z 门、控制字节、非法转义、占位符。
func validateSegCommon(st *dynState, ev *core.HL7Event, seg *core.HL7Segment, where string, sgi int) error {
	if seg.Name == "MSH" {
		return fmt.Errorf("%s segment[%d] carries user-provided MSH — MSH is auto-prepended from message_type and session fields (msh)", where, sgi)
	}
	// segment_name_invalid 自然面：3 字符 ∧ ∈ 段表白名单 ∪ 显式 Z 段
	//（D-3：Z 段未配 allow 标志即拒）。
	if len(seg.Name) != 3 {
		return fmt.Errorf("%s segment[%d] name %q invalid (must be 3 chars) (segment)", where, sgi, seg.Name)
	}
	if !knownSegmentNames[seg.Name] {
		if seg.Name[0] == 'Z' {
			if !ev.AllowZSegments && !st.sess.AllowZSegments {
				return fmt.Errorf("%s segment[%d] Z segment %q present but allow_z_segments is not set (z)", where, sgi, seg.Name)
			}
		} else {
			return fmt.Errorf("%s segment[%d] name %q is not in the known segment table (segment)", where, sgi, seg.Name)
		}
	}
	for fi, f := range seg.Fields {
		sv, ok := f.(string)
		if !ok {
			continue
		}
		// framing_control_byte 自然面：字段值携带未转义控制字节 0x0B/0x1C
		//（§3.3 正文控制字节必须转义——字符串字段直查字节）。
		if strings.ContainsAny(sv, "\x0b\x1c") {
			return fmt.Errorf("%s segment[%d].field[%d] carries an unescaped MLLP control byte (escape or remove it) (mllp)", where, sgi, fi)
		}
		// escape_invalid 自然面：\X 序列十六进制须成对（§3.3）。
		if bad := invalidHexEscape(sv); bad != "" {
			return fmt.Errorf("%s segment[%d].field[%d] invalid escape sequence %q (\\X hex must come in pairs) (escape)", where, sgi, fi, bad)
		}
		// 契约 §6 占位符门（终审 F11）：未知占位/未备资源占位即拒。
		if err := st.scanPlaceholders(where, sgi, fi, sv); err != nil {
			return err
		}
	}
	return nil
}

// invalidHexEscape returns the first malformed \X.. escape in s ("": none).
// Only the \X hex form is length-checked here; the single-letter escapes
// (\F \S \R \E \T \H \N) and \C/\M forms pass through (contract §3.3).
func invalidHexEscape(s string) string {
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		if i+1 < len(s) && s[i+1] == 'X' {
			j := i + 2
			for j < len(s) && s[j] != '\\' {
				j++
			}
			if j >= len(s) {
				return s[i:min(i+8, len(s))]
			}
			hexPart := s[i+2 : j]
			if len(hexPart) == 0 || len(hexPart)%2 != 0 {
				return s[i : j+1]
			}
			for k := 0; k < len(hexPart); k++ {
				c := hexPart[k]
				if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
					return s[i : j+1]
				}
			}
			i = j
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// validateMessageType checks message type structure (code^event^structure)
// and the MSH-9 code domain (msh9_domain 自然面：XYZ 等未知码拒).
func validateMessageType(msgType string) error {
	parts := strings.Split(msgType, "^")
	// 契约 §6 Validate 行："消息类型 3 组件合法（§3.4）"——三组件全非空
	//（2 组件 + 无 required_segment 结构键 = 裸 MSH 消息，终审 F6 探针实证）。
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return fmt.Errorf("message_type %q must be 3-component code^event^structure (msh)", msgType)
	}
	code := parts[0]
	if len(code) != 3 {
		return fmt.Errorf("message_type code %q invalid (3 chars) (msh)", code)
	}
	if !knownMessageCodes[code] {
		return fmt.Errorf("message_type code %q is not in the known MSH-9 domain (ADT/ORU/SIU/ACK/ORM/MDM/DFT) (msh)", code)
	}
	return nil
}

// isValidAckCodeOrObject returns true if the ack spec is a valid form
// (ack_code_invalid 自然面收口：码 ∉ {AA,AE,AR} 即拒).
func isValidAckCodeOrObject(s string) bool {
	if s == "AA" || s == "AE" || s == "AR" {
		return true
	}
	// try JSON parse
	if strings.HasPrefix(s, "{") {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(s), &obj); err != nil {
			return false
		}
		if code, ok := obj["code"].(string); ok {
			return code == "AA" || code == "AE" || code == "AR"
		}
	}
	return false
}
