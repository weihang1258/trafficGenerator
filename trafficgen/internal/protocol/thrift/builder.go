package thrift

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TType constants (§2.1).
const (
	TStop    = 0
	TBool    = 2
	TByte    = 3
	TDouble  = 4
	TI16     = 6
	TI32     = 8
	TI64     = 10
	TString  = 11
	TStruct  = 12
	TMap     = 13
	TSet     = 14
	TList    = 15
)

// Message type constants (§2.2).
const (
	MCall      = 1
	MReply     = 2
	MException = 3
	MOneway    = 4
)

// versionType builds the strict version_type header (0x80010000 | messageType).
func versionType(mt byte) int32 {
	return int32(0x80010000 | uint32(mt))
}

// typeCode maps a config type string to a TType byte.
func typeCode(s string) (byte, bool) {
	switch s {
	case "STOP":
		return TStop, true
	case "BOOL":
		return TBool, true
	case "BYTE":
		return TByte, true
	case "DOUBLE":
		return TDouble, true
	case "I16":
		return TI16, true
	case "I32":
		return TI32, true
	case "I64":
		return TI64, true
	case "STRING", "BINARY":
		return TString, true
	case "STRUCT":
		return TStruct, true
	case "MAP":
		return TMap, true
	case "SET":
		return TSet, true
	case "LIST":
		return TList, true
	}
	return 0, false
}

// msgType maps a config message type string to a byte.
func msgType(s string) (byte, bool) {
	switch s {
	case "CALL":
		return MCall, true
	case "REPLY":
		return MReply, true
	case "EXCEPTION":
		return MException, true
	case "ONEWAY":
		return MOneway, true
	}
	return 0, false
}

// buildMessage assembles a complete Thrift Binary Protocol message.
func buildMessage(mt byte, method string, seqid int32, body []byte) []byte {
	m := method
	nameLen := len(m)
	vt := versionType(mt)
	b := make([]byte, 0, 12+nameLen+len(body))
	b = appendI32(b, vt)
	b = appendI32(b, int32(nameLen))
	b = append(b, []byte(m)...)
	b = appendI32(b, seqid)
	b = append(b, body...)
	return b
}

// buildField writes a single struct field: type(1) + id(i16) + value.
func buildField(id int16, typeByte byte, f core.ThriftField) ([]byte, error) {
	b := make([]byte, 0, 3)
	b = append(b, typeByte)
	b = appendI16(b, id)
	vb, err := encodeValue(typeByte, f)
	if err != nil {
		return nil, err
	}
	b = append(b, vb...)
	return b, nil
}

// fieldTypeInfo resolves a field's effective TType: TypeCode override wins
// (negative tests inject out-of-range codes); otherwise the declared type
// string. ok=false on unknown type strings.
func fieldTypeInfo(f core.ThriftField) (byte, bool) {
	if f.TypeCode != 0 {
		return byte(f.TypeCode), true
	}
	return typeCode(f.Type)
}

// encodeValue encodes a value of the given TType; f carries container
// declarations (elem_type/key_type/value_type/values/entries) and BINARY
// bytes for the structured field forms.
func encodeValue(typeByte byte, f core.ThriftField) ([]byte, error) {
	value := f.Value
	switch typeByte {
	case TBool:
		v, _ := toBool(value)
		if v {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case TByte:
		return []byte{byte(toInt(value))}, nil
	case TDouble:
		v, ok := toFloat64(value)
		if !ok {
			return nil, fmt.Errorf("thrift: double requires number")
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, math.Float64bits(v))
		return b, nil
	case TI16:
		return appendI16(nil, int16(toInt(value))), nil
	case TI32:
		return appendI32(nil, int32(toInt(value))), nil
	case TI64:
		return appendI64(nil, int64(toInt(value))), nil
	case TString:
		if len(f.ValueB64) > 0 {
			b := make([]byte, 4+len(f.ValueB64))
			binary.BigEndian.PutUint32(b[0:4], uint32(len(f.ValueB64)))
			copy(b[4:], f.ValueB64)
			return b, nil
		}
		s := fmt.Sprint(value)
		b := make([]byte, 4+len(s))
		binary.BigEndian.PutUint32(b[0:4], uint32(len(s)))
		copy(b[4:], s)
		return b, nil
	case TStruct:
		return nil, fmt.Errorf("thrift: struct encoding not supported directly")
	case TList, TSet:
		arr := f.Values
		if arr == nil {
			if v, ok := value.([]interface{}); ok {
				arr = v
			}
		}
		et, ok := typeCode(f.ElemType)
		if !ok {
			et = TBool
		}
		b := []byte{et}
		b = appendI32(b, int32(len(arr)))
		for _, item := range arr {
			eb, err := encodeValue(et, core.ThriftField{Value: item})
			if err != nil {
				return nil, err
			}
			b = append(b, eb...)
		}
		return b, nil
	case TMap:
		kt, ok := typeCode(f.KeyType)
		if !ok {
			kt = TString
		}
		vt, ok := typeCode(f.ValueType)
		if !ok {
			vt = TI32
		}
		b := []byte{kt, vt}
		b = appendI32(b, int32(len(f.Entries)))
		for _, e := range f.Entries {
			kb, err := encodeValue(kt, core.ThriftField{Value: e.Key})
			if err != nil {
				return nil, err
			}
			vb, err := encodeValue(vt, core.ThriftField{Value: e.Value})
			if err != nil {
				return nil, err
			}
			b = append(b, kb...)
			b = append(b, vb...)
		}
		return b, nil
	}
	return nil, fmt.Errorf("thrift: unsupported type %d", typeByte)
}

func appendI16(b []byte, v int16) []byte {
	return append(b, byte(v>>8), byte(v))
}
func appendI32(b []byte, v int32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func appendI64(b []byte, v int64) []byte {
	return append(b, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func toInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case int32:
		return int(n)
	case int16:
		return int(n)
	case uint8:
		return int(n)
	}
	return 0
}
func toBool(v interface{}) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case float64:
		return b != 0, true
	}
	return false, false
}
func toFloat64(v interface{}) (float64, bool) {
	switch f := v.(type) {
	case float64:
		return f, true
	case int:
		return float64(f), true
	}
	return 0, false
}