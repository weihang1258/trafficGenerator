package amqp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

// AMQP 0-9-1 wire constants (AMQP 0-9-1 spec §4.2).
const (
	// ProtocolHeader is the 8-byte AMQP protocol header sent first on the
	// TCP stream: "AMQP" + protocol-id 0.9 + revision 0.1 (AMQP 0-9-1 spec).
	ProtocolHeader = "AMQP\x00\x00\x09\x01"

	// Frame types (AMQP 0-9-1 spec §4.2.1).
	FrameMethod    byte = 1
	FrameHeader    byte = 2
	FrameBody      byte = 3
	FrameHeartbeat byte = 8

	// FrameEnd is the mandatory frame terminator byte.
	FrameEnd byte = 0xCE

	// frameHeaderLen is 7 bytes: FrameType(1) + Channel(2) + Size(4).
	frameHeaderLen = 1 + 2 + 4
)

const (
	// Class and method IDs from the AMQP 0-9-1 spec §4.2.4 tables.
	classConnection uint16 = 10
	classChannel    uint16 = 20
	classExchange   uint16 = 40
	classQueue      uint16 = 50
	classBasic      uint16 = 60
	classConfirm    uint16 = 85
	classTx         uint16 = 90

	methodConnectionStart   uint16 = 10
	methodConnectionStartOK uint16 = 11
	methodConnectionTune    uint16 = 30
	methodConnectionTuneOK  uint16 = 31
	methodConnectionOpen    uint16 = 40
	methodConnectionOpenOK  uint16 = 41
	methodConnectionClose   uint16 = 50
	methodConnectionCloseOK uint16 = 51
	methodChannelOpen       uint16 = 10
	methodChannelOpenOK     uint16 = 11
	methodChannelClose      uint16 = 40
	methodChannelCloseOK    uint16 = 41
	methodExchangeDeclare   uint16 = 10
	methodExchangeDeclareOK uint16 = 11
	methodQueueDeclare      uint16 = 10
	methodQueueDeclareOK    uint16 = 11
	methodBasicConsume      uint16 = 20
	methodBasicConsumeOK    uint16 = 21
	methodBasicCancel       uint16 = 30
	methodBasicCancelOK     uint16 = 31
	methodBasicDeliver      uint16 = 60
	methodBasicGet          uint16 = 70
	methodBasicGetOK        uint16 = 71
	methodBasicGetEmpty     uint16 = 72
	methodBasicAck          uint16 = 80
	methodBasicPublish      uint16 = 40
	methodConfirmSelect     uint16 = 10
	methodTxSelect          uint16 = 10
	methodTxSelectOK        uint16 = 11
	methodTxCommit          uint16 = 20
	methodTxCommitOK        uint16 = 21
	methodTxRollback        uint16 = 30
	methodTxRollbackOK      uint16 = 31
)

// buildProtocolHeader returns the 8-byte AMQP protocol header.
func buildProtocolHeader() []byte { return []byte(ProtocolHeader) }

// buildMethodFrame builds a METHOD frame.
// Payload: class-id(2) | method-id(2) | arguments. Size covers the whole
// payload; the frame ends with the 0xCE end marker.
func buildMethodFrame(channel uint16, classID, methodID uint16, payload []byte) []byte {
	body := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(body[0:2], classID)
	binary.BigEndian.PutUint16(body[2:4], methodID)
	copy(body[4:], payload)
	return buildFrame(FrameMethod, channel, body)
}

// buildHeaderFrame builds a CONTENT HEADER frame for a message.
// Payload: class(2)=60 | weight(2)=0 | body-size(8) | property-flags(2+)
// | properties. bodySizeOverride is a negative-test knob that desynchronizes
// the declared BodySize from the actual BODY frames.
func buildHeaderFrame(channel uint16, classID uint16, bodySize uint64, props map[string]any, bodySizeOverride *uint64) ([]byte, error) {
	if bodySizeOverride != nil {
		bodySize = *bodySizeOverride
	}
	flags, propBytes, err := encodeProperties(props)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 2+2+8+2+len(propBytes))
	binary.BigEndian.PutUint16(payload[0:2], classID)
	binary.BigEndian.PutUint16(payload[2:4], 0) // weight = 0
	binary.BigEndian.PutUint64(payload[4:12], bodySize)
	binary.BigEndian.PutUint16(payload[12:14], flags)
	copy(payload[14:], propBytes)
	return buildFrame(FrameHeader, channel, payload), nil
}

// buildBodyFrame builds a BODY frame carrying body bytes.
func buildBodyFrame(channel uint16, body []byte) []byte {
	return buildFrame(FrameBody, channel, body)
}

// buildHeartbeatFrame builds the fixed HEARTBEAT frame:
// 08 00 00 00 00 00 00 ce (type=8, channel=0, size=0, end=CE).
func buildHeartbeatFrame() []byte {
	return buildFrame(FrameHeartbeat, 0, nil)
}

// buildFrame assembles one AMQP frame:
// FrameType(1) | Channel(2) | Size(4) | Payload(Size) | FrameEnd(0xCE).
func buildFrame(frameType byte, channel uint16, payload []byte) []byte {
	buf := make([]byte, frameHeaderLen+len(payload)+1)
	buf[0] = frameType
	binary.BigEndian.PutUint16(buf[1:3], channel)
	binary.BigEndian.PutUint32(buf[3:7], uint32(len(payload)))
	copy(buf[7:], payload)
	buf[len(buf)-1] = FrameEnd
	return buf
}

// encodeShortstr encodes an AMQP short string: length(1) + UTF-8 bytes.
// Short strings are at most 255 bytes (AMQP 0-9-1 spec §4.2.5.4).
func encodeShortstr(s string) ([]byte, error) {
	if len(s) > 255 {
		return nil, fmt.Errorf("shortstr too long: %d bytes (max 255)", len(s))
	}
	buf := make([]byte, 1+len(s))
	buf[0] = byte(len(s))
	copy(buf[1:], s)
	return buf, nil
}

// encodeLongstr encodes an AMQP long string: length(4) + bytes.
func encodeLongstr(b []byte) []byte {
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(b)))
	copy(buf[4:], b)
	return buf
}

// encodeLongstrStr encodes a string as a long string.
func encodeLongstrStr(s string) []byte { return encodeLongstr([]byte(s)) }

// encodeFieldTable encodes a field table: entry-count(4) + entries.
// Each entry is a longstr key + type byte + typed value (AMQP 0-9-1 spec
// §4.2.5.6). Supported types: S (shortstr), I (int32), l (int64), t (bool),
// T (table, nested).
func encodeFieldTable(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	entries := make([]byte, 0)
	for _, k := range keys {
		kb, err := encodeShortstr(k)
		if err != nil {
			return nil, err
		}
		entries = append(entries, kb...)
		vb, err := encodeFieldValue(m[k])
		if err != nil {
			return nil, err
		}
		entries = append(entries, vb...)
	}
	buf := make([]byte, 4+len(entries))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(m)))
	copy(buf[4:], entries)
	return buf, nil
}

// encodeFieldValue encodes one typed field-table value.
func encodeFieldValue(v any) ([]byte, error) {
	switch t := v.(type) {
	case string:
		sb, err := encodeShortstr(t)
		if err != nil {
			return nil, err
		}
		return append([]byte{'S'}, sb...), nil
	case int32:
		buf := make([]byte, 5)
		buf[0] = 'I'
		binary.BigEndian.PutUint32(buf[1:5], uint32(t))
		return buf, nil
	case int64:
		buf := make([]byte, 9)
		buf[0] = 'l'
		binary.BigEndian.PutUint64(buf[1:9], uint64(t))
		return buf, nil
	case bool:
		b := byte(0)
		if t {
			b = 1
		}
		return []byte{'t', b}, nil
	case map[string]any:
		tb, err := encodeFieldTable(t)
		if err != nil {
			return nil, err
		}
		return append([]byte{'T'}, tb...), nil
	case nil:
		// AMQP 0-9-1 has no nil type; encode as empty shortstr 'S' + len 0.
		return []byte{'S', 0}, nil
	default:
		return nil, fmt.Errorf("unsupported field-table value type %T", v)
	}
}

// encodeMethodArguments encodes method arguments for known method IDs using
// the argument order declared in the AMQP 0-9-1 spec §4.2.4 tables.
// Bit fields pack LSB-first into bytes in-place at the position where the
// first bit field of a contiguous run appears (AMQP 0-9-1 has no leading
// flags word ahead of the non-bit fields, unlike 0-8/0-9); each run of bit
// fields is flushed to one byte when a non-bit field follows or at the end.
func encodeMethodArguments(classID, methodID uint16, args map[string]any) ([]byte, error) {
	// Build the argument list in spec order.
	type arg struct {
		name     string
		wireType byte // 'b' bit, 'o' octet, 'S' shortstr, 'l' longstr, 'H' short, 'I' long, 'L' longlong, 't' table
	}
	// Use a generic encoder: the caller gives a list of (name, type) and we
	// emit each argument's bytes in order.
	bt := methodArgOrder(classID, methodID)
	out := make([]byte, 0)
	var bitBuf byte
	var bitCount uint
	flushBits := func() {
		if bitCount > 0 {
			out = append(out, bitBuf)
			bitBuf = 0
			bitCount = 0
		}
	}
	for _, a := range bt {
		v, ok := args[a.name]
		if !ok {
			switch a.wireType {
			case 'b':
				// Unset bit arguments default to false.
				v = false
			case 'H', 'I', 'o':
				v = int32(0)
			case 'L':
				v = int64(0)
			case 't':
				v = map[string]any{}
			default:
				v = ""
			}
		}
		switch a.wireType {
		case 'b':
			if toBool(v) {
				bitBuf |= 1 << bitCount
			}
			bitCount++
			if bitCount == 8 {
				flushBits()
			}
		case 'o':
			flushBits()
			n, err := toInt32(v)
			if err != nil {
				return nil, fmt.Errorf("argument %s: %w", a.name, err)
			}
			out = append(out, byte(n))
		case 'S':
			flushBits()
			s := fmt.Sprintf("%v", v)
			sb, err := encodeShortstr(s)
			if err != nil {
				return nil, fmt.Errorf("argument %s: %w", a.name, err)
			}
			out = append(out, sb...)
		case 'l':
			flushBits()
			s := fmt.Sprintf("%v", v)
			out = append(out, encodeLongstrStr(s)...)
		case 'H':
			// AMQP 0-9-1 "short" (16-bit) argument, e.g. ticket (spec §4.2.5.2).
			flushBits()
			n, err := toInt32(v)
			if err != nil {
				return nil, fmt.Errorf("argument %s: %w", a.name, err)
			}
			buf := make([]byte, 2)
			binary.BigEndian.PutUint16(buf, uint16(n))
			out = append(out, buf...)
		case 'I':
			flushBits()
			n, err := toInt32(v)
			if err != nil {
				return nil, fmt.Errorf("argument %s: %w", a.name, err)
			}
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, uint32(n))
			out = append(out, buf...)
		case 'L':
			flushBits()
			n, err := toInt64(v)
			if err != nil {
				return nil, fmt.Errorf("argument %s: %w", a.name, err)
			}
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, uint64(n))
			out = append(out, buf...)
		case 't':
			flushBits()
			tb, err := encodeFieldTable(v.(map[string]any))
			if err != nil {
				return nil, fmt.Errorf("argument %s: %w", a.name, err)
			}
			out = append(out, tb...)
		default:
			return nil, fmt.Errorf("unknown wire type %q for %s.%s arg %s", a.wireType, className(classID), methodName(classID, methodID), a.name)
		}
	}
	flushBits()
	return out, nil
}

func toInt32(v any) (int32, error) {
	switch t := v.(type) {
	case int32:
		return t, nil
	case float64:
		return int32(t), nil
	case int:
		return int32(t), nil
	case uint32:
		return int32(t), nil
	case uint16:
		return int32(t), nil
	}
	return 0, fmt.Errorf("cannot convert %T to int32", v)
}

func toInt64(v any) (int64, error) {
	switch t := v.(type) {
	case int64:
		return t, nil
	case float64:
		return int64(t), nil
	case int32:
		return int64(t), nil
	case int:
		return int64(t), nil
	case uint32:
		return int64(t), nil
	case uint16:
		return int64(t), nil
	}
	return 0, fmt.Errorf("cannot convert %T to int64", v)
}

func toUint32(v any) (uint32, error) {
	switch t := v.(type) {
	case uint32:
		return t, nil
	case float64:
		return uint32(t), nil
	case int32:
		return uint32(t), nil
	case int:
		return uint32(t), nil
	case uint16:
		return uint32(t), nil
	}
	return 0, fmt.Errorf("cannot convert %T to uint32", v)
}

// toBool coerces config values to bool for bit-field arguments. JSON booleans
// arrive as bool; the unit tests also pass int32 0/1 and rabbitmq style
// numeric flags. Non-zero numbers and true are truthy.
func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case int32:
		return t != 0
	case int64:
		return t != 0
	case int:
		return t != 0
	case uint32:
		return t != 0
	case uint16:
		return t != 0
	case float64:
		return t != 0
	case string:
		return t != "" && t != "false" && t != "0"
	}
	return false
}

func className(classID uint16) string {
	switch classID {
	case classConnection:
		return "connection"
	case classChannel:
		return "channel"
	case classExchange:
		return "exchange"
	case classQueue:
		return "queue"
	case classBasic:
		return "basic"
	case classConfirm:
		return "confirm"
	case classTx:
		return "tx"
	default:
		return fmt.Sprintf("class-%d", classID)
	}
}

func methodName(classID, methodID uint16) string {
	switch {
	case classID == classConnection:
		switch methodID {
		case methodConnectionStart:
			return "start"
		case methodConnectionStartOK:
			return "start-ok"
		case methodConnectionTune:
			return "tune"
		case methodConnectionTuneOK:
			return "tune-ok"
		case methodConnectionOpen:
			return "open"
		case methodConnectionOpenOK:
			return "open-ok"
		case methodConnectionClose:
			return "close"
		case methodConnectionCloseOK:
			return "close-ok"
		}
	case classID == classChannel:
		switch methodID {
		case methodChannelOpen:
			return "open"
		case methodChannelOpenOK:
			return "open-ok"
		case methodChannelClose:
			return "close"
		case methodChannelCloseOK:
			return "close-ok"
		}
	case classID == classExchange:
		switch methodID {
		case methodExchangeDeclare:
			return "declare"
		case methodExchangeDeclareOK:
			return "declare-ok"
		}
	case classID == classQueue:
		switch methodID {
		case methodQueueDeclare:
			return "declare"
		case methodQueueDeclareOK:
			return "declare-ok"
		}
	case classID == classBasic:
		switch methodID {
		case methodBasicConsume:
			return "consume"
		case methodBasicConsumeOK:
			return "consume-ok"
		case methodBasicCancel:
			return "cancel"
		case methodBasicCancelOK:
			return "cancel-ok"
		case methodBasicDeliver:
			return "deliver"
		case methodBasicGet:
			return "get"
		case methodBasicGetOK:
			return "get-ok"
		case methodBasicGetEmpty:
			return "get-empty"
		case methodBasicAck:
			return "ack"
		case methodBasicPublish:
			return "publish"
		}
	case classID == classConfirm && methodID == methodConfirmSelect:
		return "select"
	case classID == classTx:
		switch methodID {
		case methodTxSelect:
			return "select"
		case methodTxSelectOK:
			return "select-ok"
		case methodTxCommit:
			return "commit"
		case methodTxCommitOK:
			return "commit-ok"
		case methodTxRollback:
			return "rollback"
		case methodTxRollbackOK:
			return "rollback-ok"
		}
	}
	return fmt.Sprintf("%d", methodID)
}

// methodArgOrder returns the argument (name, wire type) table for a method
// in the order the AMQP 0-9-1 spec §4.2.4 declares them. wireType: 'b' bit,
// 'S' shortstr, 'l' longstr, 'L' long-long, 'I' long, 't' table, 'x' raw.
func methodArgOrder(classID, methodID uint16) []struct {
	name     string
	wireType byte
} {
	type a = struct {
		name     string
		wireType byte
	}
	if classID == classConnection {
		switch methodID {
		case methodConnectionStart:
			return []a{{"version_major", 'o'}, {"version_minor", 'o'}, {"server_properties", 't'}, {"mechanisms", 'l'}, {"locales", 'l'}}
		case methodConnectionStartOK:
			return []a{{"client_properties", 't'}, {"mechanism", 'S'}, {"response", 'l'}, {"locale", 'S'}}
		case methodConnectionTune:
			return []a{{"channel_max", 'I'}, {"frame_max", 'I'}, {"heartbeat", 'I'}}
		case methodConnectionTuneOK:
			return []a{{"channel_max", 'I'}, {"frame_max", 'I'}, {"heartbeat", 'I'}}
		case methodConnectionOpen:
			return []a{{"virtual_host", 'S'}, {"capabilities", 'S'}, {"insist", 'b'}}
		case methodConnectionOpenOK:
			return []a{{"known_hosts", 'S'}}
		case methodConnectionClose:
			return []a{{"reply_code", 'I'}, {"reply_text", 'S'}, {"class_id", 'I'}, {"method_id", 'I'}}
		case methodConnectionCloseOK:
			return []a{}
		}
	}
	if classID == classChannel {
		switch methodID {
		case methodChannelOpen:
			return []a{{"out_of_band", 'S'}}
		case methodChannelOpenOK:
			return []a{{"channel_id", 'l'}}
		case methodChannelClose:
			return []a{{"reply_code", 'I'}, {"reply_text", 'S'}, {"class_id", 'I'}, {"method_id", 'I'}}
		case methodChannelCloseOK:
			return []a{}
		}
	}
	if classID == classExchange && methodID == methodExchangeDeclare {
		return []a{{"ticket", 'H'}, {"exchange", 'S'}, {"type", 'S'}, {"passive", 'b'}, {"durable", 'b'}, {"auto_delete", 'b'}, {"internal", 'b'}, {"nowait", 'b'}, {"arguments", 't'}}
	}
	if classID == classQueue && methodID == methodQueueDeclare {
		return []a{{"ticket", 'H'}, {"queue", 'S'}, {"passive", 'b'}, {"durable", 'b'}, {"exclusive", 'b'}, {"auto_delete", 'b'}, {"nowait", 'b'}, {"arguments", 't'}}
	}
	if classID == classQueue && methodID == methodQueueDeclareOK {
		return []a{{"queue", 'S'}, {"message_count", 'I'}, {"consumer_count", 'I'}}
	}
	if classID == classBasic {
		switch methodID {
		case methodBasicConsume:
			return []a{{"ticket", 'H'}, {"queue", 'S'}, {"consumer_tag", 'S'}, {"no_local", 'b'}, {"no_ack", 'b'}, {"exclusive", 'b'}, {"nowait", 'b'}, {"arguments", 't'}}
		case methodBasicConsumeOK:
			return []a{{"consumer_tag", 'S'}}
		case methodBasicCancel:
			return []a{{"consumer_tag", 'S'}, {"nowait", 'b'}}
		case methodBasicCancelOK:
			return []a{{"consumer_tag", 'S'}}
		case methodBasicDeliver:
			return []a{{"consumer_tag", 'S'}, {"delivery_tag", 'L'}, {"redelivered", 'b'}, {"exchange", 'S'}, {"routing_key", 'S'}}
		case methodBasicGet:
			return []a{{"ticket", 'H'}, {"queue", 'S'}, {"no_ack", 'b'}}
		case methodBasicGetOK:
			return []a{{"delivery_tag", 'L'}, {"redelivered", 'b'}, {"exchange", 'S'}, {"routing_key", 'S'}, {"message_count", 'I'}}
		case methodBasicGetEmpty:
			return []a{{"cluster_id", 'S'}}
		case methodBasicAck:
			return []a{{"delivery_tag", 'L'}, {"multiple", 'b'}}
		case methodBasicPublish:
			return []a{{"ticket", 'H'}, {"exchange", 'S'}, {"routing_key", 'S'}, {"mandatory", 'b'}, {"immediate", 'b'}}
		}
	}
	if classID == classConfirm && methodID == methodConfirmSelect {
		return []a{{"nowait", 'b'}}
	}
	if classID == classTx {
		switch methodID {
		case methodTxSelect:
			return []a{}
		case methodTxCommit:
			return []a{}
		case methodTxRollback:
			return []a{}
		}
	}
	// Unknown method: no arguments.
	return []a{}
}

// propertyFlagIndexes maps content-header property names to their bit index
// in the property flags word (AMQP 0-9-1 spec §4.2.6, class 60 table).
var propertyFlagIndexes = map[string]uint{
	"content_type":     15,
	"content_encoding": 14,
	"headers":          13,
	"delivery_mode":    12,
	"priority":         11,
	"correlation_id":   10,
	"reply_to":         9,
	"expiration":       8,
	"message_id":       7,
	"timestamp":        6,
	"type":             5,
	"user_id":          4,
	"app_id":           3,
	"cluster_id":       2,
}

// encodeProperties encodes content header property flags + bytes.
// Each property is encoded with its own wire type; the flags word has bit i
// set when the property is present.
func encodeProperties(props map[string]any) (uint16, []byte, error) {
	names := make([]string, 0, len(props))
	for n := range props {
		if _, ok := propertyFlagIndexes[n]; !ok {
			return 0, nil, fmt.Errorf("unknown property %q", n)
		}
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		return propertyFlagIndexes[names[i]] > propertyFlagIndexes[names[j]]
	})
	var flags uint16
	out := make([]byte, 0)
	for _, n := range names {
		idx := propertyFlagIndexes[n]
		flags |= 1 << idx
		switch n {
		case "content_type", "content_encoding", "correlation_id", "reply_to",
			"expiration", "message_id", "type", "user_id", "app_id", "cluster_id":
			s, err := encodeShortstr(fmt.Sprintf("%v", props[n]))
			if err != nil {
				return 0, nil, fmt.Errorf("property %s: %w", n, err)
			}
			out = append(out, s...)
		case "delivery_mode", "priority":
			buf := make([]byte, 1)
			buf[0] = byte(numFromAny(props[n]))
			out = append(out, buf...)
		case "timestamp":
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, uint64(numFromAny(props[n])))
			out = append(out, buf...)
		case "headers":
			tb, err := encodeFieldTable(props[n].(map[string]any))
			if err != nil {
				return 0, nil, fmt.Errorf("property headers: %w", err)
			}
			out = append(out, tb...)
		}
	}
	return flags, out, nil
}

// numFromAny converts any JSON-ish numeric to a uint64, defaulting to 0.
func numFromAny(v any) uint64 {
	switch t := v.(type) {
	case float64:
		return uint64(t)
	case int:
		return uint64(t)
	case int32:
		return uint64(t)
	case int64:
		return uint64(t)
	case uint32:
		return uint64(t)
	case uint16:
		return uint64(t)
	}
	return 0
}

// resolveBody returns an event's body bytes: body_hex takes precedence over
// body (mirroring the RTMFP message_b64 -> message precedence). Body is
// `any` from JSON: a string stays as-is, []byte arrives only when constructed
// programmatically (e.g. unit tests).
func resolveBody(body any, bodyHex string) []byte {
	if bodyHex != "" {
		if b, err := hex.DecodeString(bodyHex); err == nil {
			return b
		}
	}
	switch b := body.(type) {
	case string:
		return []byte(b)
	case []byte:
		return b
	case nil:
		return nil
	default:
		return []byte(fmt.Sprintf("%v", b))
	}
}

// splitBody splits body bytes into BODY-frame chunks so that each frame's
// full wire length (7 + size + 1) does not exceed frameMax. frameMax == 0
// (AMQP default) means unbounded: a single BODY frame for the whole body.
// The AMQP spec's minimum frame_max is 4096 (spec §4.2.1).
func splitBody(body []byte, frameMax uint32) [][]byte {
	if frameMax > 0 {
		const minPayload = 4096 - 8 // conservative: leave room for header+end
		if frameMax >= 8 && frameMax <= minPayload {
			// Stress fixture: frame_max is intentionally tiny in tests;
			// payload per frame = frameMax - 8.
			chunk := int(frameMax) - 8
			if chunk < 1 {
				chunk = 1
			}
			out := make([][]byte, 0, (len(body)+chunk-1)/chunk)
			for len(body) > 0 {
				n := chunk
				if n > len(body) {
					n = len(body)
				}
				out = append(out, body[:n])
				body = body[n:]
			}
			return out
		}
	}
	chunk := int(frameMax) - 8
	if chunk < 1 {
		// frame_max 0 (AMQP default = unbounded) or too small: single frame.
		return [][]byte{body}
	}
	out := make([][]byte, 0, (len(body)+chunk-1)/chunk)
	for len(body) > 0 {
		n := chunk
		if n > len(body) {
			n = len(body)
		}
		out = append(out, body[:n])
		body = body[n:]
	}
	return out
}
