package mongodb

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"

	"github.com/trafficgen/trafficgen/internal/core"
)

// MongoDB wire protocol opcodes.
const (
	OpReply        = 1
	OpUpdate       = 2001
	OpInsert       = 2002
	OpQuery        = 2004
	OpGetMore      = 2005
	OpDelete       = 2006
	OpKillCursors  = 2007
)

// BSON element type constants.
const (
	BSONDouble   byte = 0x01
	BSONString   byte = 0x02
	BSONDoc      byte = 0x03
	BSONArray    byte = 0x04
	BSONBinary   byte = 0x05
	BSONBool     byte = 0x08
	BSONNull     byte = 0x0A
	BSONInt32    byte = 0x10
	BSONInt64    byte = 0x12
)

// HeaderSize is the MongoDB wire protocol header size.
const HeaderSize = 16

// MaxMessagePayload is the maximum allowed message payload size (4 MB).
const MaxMessagePayload = 4 << 20

// opcodeForOp maps an opcode string to its int32 value.
func opcodeForOp(s string) (int32, bool) {
	switch s {
	case "OP_REPLY":
		return OpReply, true
	case "OP_UPDATE":
		return OpUpdate, true
	case "OP_INSERT":
		return OpInsert, true
	case "OP_QUERY":
		return OpQuery, true
	case "OP_GET_MORE":
		return OpGetMore, true
	case "OP_DELETE":
		return OpDelete, true
	case "OP_KILL_CURSORS":
		return OpKillCursors, true
	}
	return 0, false
}

// opcodeDirection returns the wire direction for a known opcode.
func opcodeDirection(op int32) string {
	if op == OpReply {
		return "s2c"
	}
	return "c2s"
}

// opcodeString returns the string name for an opcode.
func opcodeString(op int32) string {
	switch op {
	case OpReply:
		return "OP_REPLY"
	case OpUpdate:
		return "OP_UPDATE"
	case OpInsert:
		return "OP_INSERT"
	case OpQuery:
		return "OP_QUERY"
	case OpGetMore:
		return "OP_GET_MORE"
	case OpDelete:
		return "OP_DELETE"
	case OpKillCursors:
		return "OP_KILL_CURSORS"
	}
	return fmt.Sprintf("UNKNOWN(%d)", op)
}

// buildHeader builds a 16-byte MongoDB wire protocol header (little-endian).
func buildHeader(requestID, responseTo, opCode int32, body []byte) []byte {
	msgLen := HeaderSize + len(body)
	b := make([]byte, HeaderSize+len(body))
	binary.LittleEndian.PutUint32(b[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(b[4:8], uint32(requestID))
	binary.LittleEndian.PutUint32(b[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(b[12:16], uint32(opCode))
	copy(b[16:], body)
	return b
}

// buildBSON builds a BSON document from a Go map.
func buildBSON(doc map[string]interface{}) []byte {
	if len(doc) == 0 {
		// Empty BSON: int32(5) + 0x00 = 5 bytes
		return []byte{0x05, 0x00, 0x00, 0x00, 0x00}
	}
	var elements []byte
	for k, v := range doc {
		elements = append(elements, bsonElement(k, v)...)
	}
	elements = append(elements, 0x00) // terminator
	// Prepend totalSize
	totalSize := int32(4 + len(elements))
	out := make([]byte, 4+len(elements))
	binary.LittleEndian.PutUint32(out[0:4], uint32(totalSize))
	copy(out[4:], elements)
	return out
}

// bsonElement builds one BSON element: typeByte + fieldName\0 + value.
func bsonElement(name string, val interface{}) []byte {
	cname := append([]byte(name), 0)
	switch v := val.(type) {
	case float64:
		// JSON numbers are float64; check if it's a whole number
		if v == math.Trunc(v) && v >= math.MinInt32 && v <= math.MaxInt32 {
			return bsonInt32Element(cname, int32(v))
		}
		return bsonDoubleElement(cname, v)
	case int:
		return bsonInt32Element(cname, int32(v))
	case int32:
		return bsonInt32Element(cname, v)
	case int64:
		return bsonInt64Element(cname, v)
	case string:
		return bsonStringElement(cname, v)
	case bool:
		return bsonBoolElement(cname, v)
	case nil:
		return bsonNullElement(cname)
	case map[string]interface{}:
		return bsonDocElement(cname, v)
	case []interface{}:
		return bsonArrayElement(cname, v)
	}
	return bsonNullElement(cname)
}

func bsonDoubleElement(cname []byte, v float64) []byte {
	b := []byte{BSONDouble}
	b = append(b, cname...)
	b = appendU64(b, math.Float64bits(v))
	return b
}

func bsonStringElement(cname []byte, v string) []byte {
	b := []byte{BSONString}
	b = append(b, cname...)
	// String: int32(length including null) + bytes + null
	strBytes := append([]byte(v), 0)
	b = appendI32(b, int32(len(strBytes)))
	b = append(b, strBytes...)
	return b
}

func bsonDocElement(cname []byte, doc map[string]interface{}) []byte {
	b := []byte{BSONDoc}
	b = append(b, cname...)
	b = append(b, buildBSON(doc)...)
	return b
}

func bsonArrayElement(cname []byte, arr []interface{}) []byte {
	b := []byte{BSONArray}
	b = append(b, cname...)
	// Build a document with numeric keys
	doc := make(map[string]interface{})
	for i, v := range arr {
		doc[fmt.Sprintf("%d", i)] = v
	}
	b = append(b, buildBSON(doc)...)
	return b
}

func bsonInt32Element(cname []byte, v int32) []byte {
	b := []byte{BSONInt32}
	b = append(b, cname...)
	b = appendI32(b, v)
	return b
}

func bsonInt64Element(cname []byte, v int64) []byte {
	b := []byte{BSONInt64}
	b = append(b, cname...)
	b = appendI64(b, v)
	return b
}

func bsonBoolElement(cname []byte, v bool) []byte {
	b := []byte{BSONBool}
	b = append(b, cname...)
	if v {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return b
}

func bsonNullElement(cname []byte) []byte {
	b := []byte{BSONNull}
	b = append(b, cname...)
	return b
}

// buildBSONList builds a sequence of concatenated BSON documents.
func buildBSONList(docs []map[string]interface{}) []byte {
	var b []byte
	for _, doc := range docs {
		b = append(b, buildBSON(doc)...)
	}
	return b
}

// buildMessage builds a MongoDB wire protocol message from a message config.
func buildMessage(msg core.MongoDBMessage) ([]byte, error) {
	var opCode int32
	switch o := msg.Opcode.(type) {
	case string:
		var ok bool
		opCode, ok = opcodeForOp(o)
		if !ok {
			return nil, fmt.Errorf("mongodb: unknown opcode %q", o)
		}
	case int32:
		opCode = o
	case float64:
		opCode = int32(o)
	default:
		// Try numeric unwrap
		return nil, fmt.Errorf("mongodb: invalid opcode type %T", msg.Opcode)
	}

	var body []byte
	switch opCode {
	case OpQuery:
		body = buildQueryBody(msg)
	case OpReply:
		body = buildReplyBody(msg)
	case OpInsert:
		body = buildInsertBody(msg)
	case OpUpdate:
		body = buildUpdateBody(msg)
	case OpDelete:
		body = buildDeleteBody(msg)
	case OpGetMore:
		body = buildGetMoreBody(msg)
	case OpKillCursors:
		body = buildKillCursorsBody(msg)
	default:
		return nil, fmt.Errorf("mongodb: unsupported opcode %d (%s)", opCode, opcodeString(opCode))
	}
	return buildHeader(msg.RequestID, msg.ResponseTo, opCode, body), nil
}

// buildQueryBody builds an OP_QUERY body.
// Format: flags(4) + namespace(CString) + skip(4) + return(4) + query(BSON).
func buildQueryBody(msg core.MongoDBMessage) []byte {
	var b []byte
	b = appendI32(b, msg.Flags)
	b = appendCString(b, msg.Namespace)
	b = appendI32(b, msg.Skip)
	b = appendI32(b, msg.ReturnCount)
	b = append(b, buildBSON(msg.Query)...)
	return b
}

// buildReplyBody builds an OP_REPLY body.
// Format: flags(4) + cursorID(8) + startingFrom(4) + returned(4) + documents(BSON list).
func buildReplyBody(msg core.MongoDBMessage) []byte {
	var b []byte
	b = appendI32(b, msg.Flags)
	b = appendI64(b, msg.CursorID)
	b = appendI32(b, msg.StartingFrom)
	b = appendI32(b, msg.Returned)
	b = append(b, buildBSONList(msg.Documents)...)
	return b
}

// buildInsertBody builds an OP_INSERT body.
// Format: flags(4) + namespace(CString) + documents(BSON list).
func buildInsertBody(msg core.MongoDBMessage) []byte {
	var b []byte
	b = appendI32(b, msg.Flags)
	b = appendCString(b, msg.Namespace)
	if msg.BSONFixtureHex != "" {
		if fix, err := parseBSONFixtureHex(msg.BSONFixtureHex); err == nil {
			b = append(b, fix...)
			return b
		}
	}
	b = append(b, buildBSONList(msg.Documents)...)
	return b
}

// buildUpdateBody builds an OP_UPDATE body.
// Format: zero(4) + namespace(CString) + flags(4) + selector(BSON) + update(BSON).
func buildUpdateBody(msg core.MongoDBMessage) []byte {
	var b []byte
	b = appendI32(b, msg.Zero)
	b = appendCString(b, msg.Namespace)
	b = appendI32(b, msg.Flags)
	b = append(b, buildBSON(msg.Selector)...)
	b = append(b, buildBSON(msg.Update)...)
	return b
}

// buildDeleteBody builds an OP_DELETE body.
// Format: zero(4) + namespace(CString) + flags(4) + selector(BSON).
func buildDeleteBody(msg core.MongoDBMessage) []byte {
	var b []byte
	b = appendI32(b, msg.Zero)
	b = appendCString(b, msg.Namespace)
	b = appendI32(b, msg.Flags)
	b = append(b, buildBSON(msg.Selector)...)
	return b
}

// buildGetMoreBody builds an OP_GET_MORE body.
// Format: zero(4) + namespace(CString) + return(4) + cursorID(8).
func buildGetMoreBody(msg core.MongoDBMessage) []byte {
	var b []byte
	b = appendI32(b, msg.Zero)
	b = appendCString(b, msg.Namespace)
	b = appendI32(b, msg.ReturnCount)
	b = appendI64(b, msg.CursorID)
	return b
}

// buildKillCursorsBody builds an OP_KILL_CURSORS body.
// Format: zero(4) + count(4) + cursorIDs(count*8).
func buildKillCursorsBody(msg core.MongoDBMessage) []byte {
	var b []byte
	b = appendI32(b, 0) // zero
	b = appendI32(b, int32(len(msg.CursorIDs)))
	for _, id := range msg.CursorIDs {
		b = appendI64(b, id)
	}
	return b
}

// parseBSONFixtureHex parses a hex-encoded BSON document and returns the raw bytes.
func parseBSONFixtureHex(hex string) ([]byte, error) {
	if len(hex) == 0 {
		return nil, nil
	}
	// Remove spaces
	cleaned := make([]byte, 0, len(hex))
	for i := 0; i < len(hex); i++ {
		if hex[i] != ' ' {
			cleaned = append(cleaned, hex[i])
		}
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("mongodb: bson_fixture_hex: odd length")
	}
	out := make([]byte, len(cleaned)/2)
	for i := 0; i < len(out); i++ {
		hi := nibble(cleaned[2*i])
		lo := nibble(cleaned[2*i+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("mongodb: bson_fixture_hex: invalid hex char")
		}
		out[i] = byte(hi<<4) | byte(lo)
	}
	return out, nil
}

func nibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// --- wireFault ---

type wireFault struct {
	Kind  string      `json:"kind"`
	Value interface{} `json:"value"`
}

// checkWireFault parses the config wire_fault and returns a config error if the
// injected fault is in scope.
func checkWireFault(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var f wireFault
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("mongodb: invalid wire_fault: %v", err)
	}
	switch f.Kind {
	case "truncate_header":
		return fmt.Errorf("mongodb: wire fault: truncated header")
	case "message_length":
		return fmt.Errorf("mongodb: wire fault: short message length")
	case "message_limit":
		return fmt.Errorf("mongodb: wire fault: message over limit")
	case "opcode":
		return fmt.Errorf("mongodb: wire fault: invalid opcode %v", f.Value)
	case "bson_length":
		return fmt.Errorf("mongodb: wire fault: bson length exceeds message boundary")
	default:
		return fmt.Errorf("mongodb: wire fault: unknown kind %q", f.Kind)
	}
}

// --- helpers (little-endian) ---

func appendI32(b []byte, v int32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendU64(b []byte, v uint64) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func appendI64(b []byte, v int64) []byte {
	return appendU64(b, uint64(v))
}

func appendCString(b []byte, s string) []byte {
	b = append(b, []byte(s)...)
	return append(b, 0)
}