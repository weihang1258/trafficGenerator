// Package ams implements the ActiveMQ Management Service (AMS) terminal
// layer (B5)：本项目 AMS wire profile——TCP 61616 上的确定性管理帧序列。
// builder.go 只做线格式编码（纯函数），状态机校验/事件折叠在 layer_gen.go。
//
// 帧布局（docs/protocol-designs/51-ams-design.md §3，network byte order）：
//
//	Length(4) | Version(1) | Type(1) | Flags(2) | SessionID(4) |
//	CorrelationID(8) | Payload(N) | FrameEnd(2)
//
// Length = 18+N（不含自身 4 字节），最小 18；FrameEnd 恒 ae 5a；Version=1
// 为唯一合法版本。Payload 由 TLV（FieldID(2)|FieldLength(2)|Value）组成，
// FieldLength 只计 Value。tshark 无本协议 dissector（61616 上的 openwire
// 启发式 magic 检查不会命中 AMS 帧），断言走 TCP 字段与帧字节。
package ams

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// 帧类型（设计 §3 Type 表）。
const (
	typeHello        = 0x01
	typeHelloOK      = 0x02
	typeAuth         = 0x03
	typeAuthOK       = 0x04
	typeOpenSession  = 0x05
	typeOpenOK       = 0x06
	typeCloseSession = 0x07
	typeCloseOK      = 0x08
	typeMessage      = 0x10
	typeMessageAck   = 0x11
	typeCommand      = 0x20
	typeResponse     = 0x21
	typePing         = 0x30
	typePong         = 0x31
	typeError        = 0x7f
)

// flags bit 语义（设计 §3）。
const (
	flagRequest     = 0x0001
	flagResponse    = 0x0002
	flagAckRequired = 0x0004
)

// TLV FieldID（设计 §4 稳定观察面）。
const (
	fieldClientName    = 0x0001
	fieldProfile       = 0x0002
	fieldAuthMethod    = 0x0004
	fieldCredentialRef = 0x0005
	fieldSessionName   = 0x0010
	fieldSessionLimit  = 0x0011
	fieldHeartbeat     = 0x0012
	fieldCommand       = 0x0020
	fieldResource      = 0x0021
	fieldBody          = 0x0022
	fieldStatus        = 0x0023
	fieldMessageID     = 0x0030
	fieldMessageKind   = 0x0031
	fieldDeliveryMode  = 0x0032
	fieldSequence      = 0x0033
	fieldPayload       = 0x0034
	fieldAckFor        = 0x0040
	fieldAckStatus     = 0x0041
	fieldAckRangeEnd   = 0x0042
	fieldErrorCode     = 0x00f0
	fieldErrorText     = 0x00f1
)

// 线格式常量。
const (
	frameVersion = 0x01
	frameEndHi   = 0xae
	frameEndLo   = 0x5a
	// headerBytes = Version(1)+Type(1)+Flags(2)+SessionID(4)+CorrelationID(8)
	// +FrameEnd(2)；Length 值 = headerBytes + len(payload)，最小 18。
	headerBytes = 18

	defaultProfile      = "ams_management_v1"
	defaultClientName   = "ams-client"
	defaultAuthMethod   = "ref"
	defaultCredential   = "cred-ref-1"
	defaultSessionLimit = 16
	defaultFrameMax     = 4096
	defaultDstPort      = 61616
)

// tlv is one encoded payload field.
type tlv struct {
	id    uint16
	value []byte
}

// tlvsBytes serialises [FieldID(2)|FieldLength(2)|Value] fields back to back。
func tlvsBytes(fields []tlv) []byte {
	var out []byte
	for _, t := range fields {
		out = binary.BigEndian.AppendUint16(out, t.id)
		out = binary.BigEndian.AppendUint16(out, uint16(len(t.value)))
		out = append(out, t.value...)
	}
	return out
}

// buildFrame encodes one AMS frame; frame total size = 4 + headerBytes +
// len(payload) = 22+N。
func buildFrame(typeByte byte, flags uint16, sessionID uint32, correlationID uint64, fields []tlv) []byte {
	payload := tlvsBytes(fields)
	out := binary.BigEndian.AppendUint32(nil, uint32(headerBytes+len(payload)))
	out = append(out, frameVersion, typeByte)
	out = binary.BigEndian.AppendUint16(out, flags)
	out = binary.BigEndian.AppendUint32(out, sessionID)
	out = binary.BigEndian.AppendUint64(out, correlationID)
	out = append(out, payload...)
	out = append(out, frameEndHi, frameEndLo)
	return out
}

// u16tlv/u64tlv/u8tlv are numeric TLV value helpers（uint16/uint64/uint8
// 大端裸值）。
func u16tlv(id uint16, v uint16) tlv {
	return tlv{id: id, value: binary.BigEndian.AppendUint16(nil, v)}
}
func u64tlv(id uint16, v uint64) tlv {
	return tlv{id: id, value: binary.BigEndian.AppendUint64(nil, v)}
}
func u8tlv(id uint16, v byte) tlv {
	return tlv{id: id, value: []byte{v}}
}
func strtlv(id uint16, s string) tlv {
	return tlv{id: id, value: []byte(s)}
}

// eventDefaults resolves the kind-derived (typeByte, flags, direction)。
// 方向缺省：_ok/pong/response/message_ack → s2c，其余 c2s（error 双向，
// 缺省 c2s）。
func eventDefaults(e *core.AMSEvent) (byte, uint16, string, bool) {
	switch e.Kind {
	case "hello":
		return typeHello, flagRequest, "c2s", true
	case "hello_ok":
		return typeHelloOK, flagResponse, "s2c", true
	case "auth":
		return typeAuth, flagRequest, "c2s", true
	case "auth_ok":
		return typeAuthOK, flagResponse, "s2c", true
	case "open_session":
		return typeOpenSession, flagRequest, "c2s", true
	case "open_ok":
		return typeOpenOK, flagResponse, "s2c", true
	case "close_session":
		return typeCloseSession, flagRequest, "c2s", true
	case "close_ok":
		return typeCloseOK, flagResponse, "s2c", true
	case "message":
		return typeMessage, flagRequest, "c2s", true
	case "message_ack":
		return typeMessageAck, flagResponse, "s2c", true
	case "command":
		return typeCommand, flagRequest, "c2s", true
	case "response":
		return typeResponse, flagResponse, "s2c", true
	case "ping":
		return typePing, flagRequest, "c2s", true
	case "pong":
		return typePong, flagResponse, "s2c", true
	case "error":
		return typeError, flagResponse, "c2s", true
	}
	return 0, 0, "", false
}

// eventFlags resolves the wire flags: kind default + ack-required for
// delivery_mode=1 messages；显式 Flags 整体覆盖（负例/特殊 fixture 用）。
func eventFlags(e *core.AMSEvent, def uint16) uint16 {
	if e.Flags != 0 {
		return uint16(e.Flags)
	}
	if e.Kind == "message" && e.DeliveryMode == 1 {
		return def | flagAckRequired
	}
	return def
}

// BuildEventFrame encodes one AMSEvent into its frame bytes, applying the
// connection/config-level defaults（profile/client_name/auth TLVs）。返回
// nil 表示 kind 未知（validator 先拒绝，防御性兜底）。
func BuildEventFrame(e *core.AMSEvent, cfg *core.AMSConfig, sessionID uint32) []byte {
	typeByte, flags, _, ok := eventDefaults(e)
	if !ok {
		return nil
	}
	if e.Type != 0 {
		typeByte = byte(e.Type)
	}
	flags = eventFlags(e, flags)
	profile := cfg.Profile
	if profile == "" {
		profile = defaultProfile
	}
	client := cfg.ClientName
	if client == "" {
		client = defaultClientName
	}
	authMethod := cfg.AuthMethod
	if authMethod == "" {
		authMethod = defaultAuthMethod
	}
	cred := cfg.CredentialRef
	if cred == "" {
		cred = defaultCredential
	}
	sessionLimit := cfg.SessionLimit
	if sessionLimit == 0 {
		sessionLimit = defaultSessionLimit
	}
	heartbeat := cfg.Heartbeat

	var fields []tlv
	switch e.Kind {
	case "hello":
		fields = []tlv{strtlv(fieldClientName, client), strtlv(fieldProfile, profile)}
	case "hello_ok":
		fields = []tlv{strtlv(fieldProfile, profile), u16tlv(fieldHeartbeat, heartbeat), u16tlv(fieldSessionLimit, sessionLimit)}
	case "auth":
		fields = []tlv{strtlv(fieldAuthMethod, authMethod), strtlv(fieldCredentialRef, cred)}
	case "auth_ok":
		fields = []tlv{u16tlv(fieldStatus, uint16(e.Status))}
	case "open_session":
		if e.SessionName != "" {
			fields = []tlv{strtlv(fieldSessionName, e.SessionName)}
		}
	case "open_ok":
		fields = []tlv{u16tlv(fieldStatus, uint16(e.Status)), u16tlv(fieldSessionLimit, sessionLimit)}
	case "close_session", "close_ok", "ping", "pong":
		// 空 payload：Length=18 最小帧（设计 §7 边界）。
	case "command":
		fields = []tlv{strtlv(fieldCommand, e.Command), strtlv(fieldResource, e.Resource)}
		if len(e.Body) > 0 {
			fields = append(fields, tlv{id: fieldBody, value: e.Body})
		}
	case "response":
		fields = []tlv{u16tlv(fieldStatus, uint16(e.Status))}
		if len(e.Body) > 0 {
			fields = append(fields, tlv{id: fieldBody, value: e.Body})
		}
	case "message":
		fields = []tlv{
			u64tlv(fieldMessageID, e.MessageID),
			strtlv(fieldMessageKind, e.MessageKind),
			u8tlv(fieldDeliveryMode, byte(e.DeliveryMode)),
			u64tlv(fieldSequence, e.Sequence),
		}
		if len(e.Payload) > 0 {
			fields = append(fields, tlv{id: fieldPayload, value: e.Payload})
		}
	case "message_ack":
		fields = []tlv{u64tlv(fieldAckFor, e.AckFor), u16tlv(fieldAckStatus, uint16(e.AckStatus))}
		if e.AckRangeEnd > 0 {
			fields = append(fields, u64tlv(fieldAckRangeEnd, e.AckRangeEnd))
		}
	case "error":
		fields = []tlv{u16tlv(fieldErrorCode, uint16(e.ErrorCode)), strtlv(fieldErrorText, e.ErrorText)}
	}
	return buildFrame(typeByte, flags, sessionID, e.CorrelationID, fields)
}

// CheckFrameMax guards the encoded size against frame_max（长度加法不得
// 无界——设计 §3/§7）。
func CheckFrameMax(frame []byte, frameMax uint32) error {
	limit := frameMax
	if limit == 0 {
		limit = defaultFrameMax
	}
	if uint64(len(frame)) > uint64(limit) {
		return fmt.Errorf("ams: frame length %d exceeds frame_max %d (length)", len(frame), limit)
	}
	return nil
}
