package thrift

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func hex(b []byte) string {
	const hextable = "0123456789abcdef"
	r := make([]byte, len(b)*2)
	for i, v := range b {
		r[i*2] = hextable[v>>4]
		r[i*2+1] = hextable[v&0x0f]
	}
	return string(r)
}

// --- Builder tests ---

func TestVersionType(t *testing.T) {
	// §2.2: version_type = 0x80010000 | message_type
	tests := []struct {
		mt   byte
		want uint32
	}{
		{MCall, 0x80010001},
		{MReply, 0x80010002},
		{MException, 0x80010003},
		{MOneway, 0x80010004},
	}
	for _, tc := range tests {
		got := uint32(versionType(tc.mt))
		if got != tc.want {
			t.Fatalf("versionType(%d)=%08x want %08x", tc.mt, got, tc.want)
		}
	}
}

func TestTypeCode(t *testing.T) {
	// §2.1 TType table
	tests := []struct {
		s    string
		want byte
		ok   bool
	}{
		{"STOP", TStop, true},
		{"BOOL", TBool, true},
		{"BYTE", TByte, true},
		{"DOUBLE", TDouble, true},
		{"I16", TI16, true},
		{"I32", TI32, true},
		{"I64", TI64, true},
		{"STRING", TString, true},
		{"BINARY", TString, true},
		{"STRUCT", TStruct, true},
		{"MAP", TMap, true},
		{"SET", TSet, true},
		{"LIST", TList, true},
		{"UNKNOWN", 0, false},
		{"", 0, false},
	}
	for _, tc := range tests {
		got, ok := typeCode(tc.s)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("typeCode(%q)=%d,%v want %d,%v", tc.s, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMsgType(t *testing.T) {
	tests := []struct {
		s    string
		want byte
		ok   bool
	}{
		{"CALL", MCall, true},
		{"REPLY", MReply, true},
		{"EXCEPTION", MException, true},
		{"ONEWAY", MOneway, true},
		{"BOGUS", 0, false},
	}
	for _, tc := range tests {
		got, ok := msgType(tc.s)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("msgType(%q)=%d,%v want %d,%v", tc.s, got, ok, tc.want, tc.ok)
		}
	}
}

func TestBuildMessageCallReply(t *testing.T) {
	// S1: CALL add(1,2) → body of two I32 fields + STOP
	body := []byte{
		0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // I32 id=1 value=1
		0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, // I32 id=2 value=2
		0x00, // STOP
	}
	msg := buildMessage(MCall, "add", 1, body)
	// version_type(4) + nameLen(4) + "add"(3) + seqid(4) + body(15) = 30
	if len(msg) != 30 {
		t.Fatalf("msg len=%d want 30", len(msg))
	}
	// version_type = 0x80010001
	if got := binary.BigEndian.Uint32(msg[0:4]); got != 0x80010001 {
		t.Fatalf("version_type=%08x want 80010001", got)
	}
	// nameLen = 3
	if got := binary.BigEndian.Uint32(msg[4:8]); got != 3 {
		t.Fatalf("nameLen=%d want 3", got)
	}
	if string(msg[8:11]) != "add" {
		t.Fatalf("method=%q want add", msg[8:11])
	}
	if got := binary.BigEndian.Uint32(msg[11:15]); got != 1 {
		t.Fatalf("seqid=%d want 1", got)
	}
	// canonical hex from design §5.1
	want := "800100010000000361646400000001080001000000010800020000000200"
	if hex(msg) != want {
		t.Fatalf("hex=%s want %s", hex(msg), want)
	}
}

func TestBuildMessageReply(t *testing.T) {
	// S1 REPLY: add → result I32 id=0 value=3
	body := []byte{
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // I32 id=0 value=3
		0x00, // STOP
	}
	msg := buildMessage(MReply, "add", 1, body)
	if len(msg) != 23 {
		t.Fatalf("msg len=%d want 23", len(msg))
	}
	// version_type = 0x80010002
	if got := binary.BigEndian.Uint32(msg[0:4]); got != 0x80010002 {
		t.Fatalf("version_type=%08x want 80010002", got)
	}
	// canonical hex from design §5.2
	want := "8001000200000003616464000000010800000000000300"
	if hex(msg) != want {
		t.Fatalf("hex=%s want %s", hex(msg), want)
	}
}

func TestBuildMessageException(t *testing.T) {
	// S2: EXCEPTION type=3
	body := []byte{
		0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, // STRING id=1 len=16
		'd', 'i', 'v', 'i', 's', 'i', 'o', 'n', ' ', 'b', 'y', ' ', 'z', 'e', 'r', 'o',
		0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, // I32 id=2 value=6
		0x00, // STOP
	}
	msg := buildMessage(MException, "divide", 7, body)
	if len(msg) != 49 {
		t.Fatalf("msg len=%d want 49", len(msg))
	}
	if got := binary.BigEndian.Uint32(msg[0:4]); got != 0x80010003 {
		t.Fatalf("version_type=%08x want 80010003", got)
	}
	if string(msg[8:14]) != "divide" {
		t.Fatalf("method=%q want divide", msg[8:14])
	}
	if got := binary.BigEndian.Uint32(msg[14:18]); got != 7 {
		t.Fatalf("seqid=%d want 7", got)
	}
}

func TestBuildMessageOneway(t *testing.T) {
	// S3: ONEWAY notify
	body := []byte{0x00} // STOP only
	msg := buildMessage(MOneway, "notify", 42, body)
	if len(msg) != 19 {
		t.Fatalf("msg len=%d want 19 (12+5+2)", len(msg))
	}
	if got := binary.BigEndian.Uint32(msg[0:4]); got != 0x80010004 {
		t.Fatalf("version_type=%08x want 80010004", got)
	}
	if string(msg[8:14]) != "notify" {
		t.Fatalf("method=%q want notify", msg[8:14])
	}
	if got := binary.BigEndian.Uint32(msg[14:18]); got != 42 {
		t.Fatalf("seqid=%d want 42", got)
	}
	// STOP ends body at index 18 (msg[18] == STOP)
	if msg[18] != TStop {
		t.Fatalf("final byte=%02x want 00", msg[18])
	}
}

func TestBuildFieldBool(t *testing.T) {
	// BOOL id=1 value=true
	b, err := buildField(1, TBool, core.ThriftField{Value: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 4 {
		t.Fatalf("len=%d want 4 (type+id+value)", len(b))
	}
	if b[0] != TBool {
		t.Fatalf("type=%02x want %02x", b[0], TBool)
	}
	if got := binary.BigEndian.Uint16(b[1:3]); got != 1 {
		t.Fatalf("id=%d want 1", got)
	}
	if b[3] != 1 {
		t.Fatalf("value=%02x want 01", b[3])
	}
}

func TestBuildFieldI32(t *testing.T) {
	// I32 id=0 value=42
	b, err := buildField(0, TI32, core.ThriftField{Value: 42})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 7 {
		t.Fatalf("len=%d want 7 (type+id+4B)", len(b))
	}
	if b[0] != TI32 {
		t.Fatalf("type=%02x want %02x", b[0], TI32)
	}
	if got := binary.BigEndian.Uint16(b[1:3]); got != 0 {
		t.Fatalf("id=%d want 0", got)
	}
	if got := binary.BigEndian.Uint32(b[3:7]); got != 42 {
		t.Fatalf("value=%d want 42", got)
	}
}

func TestBuildFieldString(t *testing.T) {
	b, err := buildField(1, TString, core.ThriftField{Value: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	// type(1) + id(2) + len(4) + "hello"(5) = 12
	if len(b) != 12 {
		t.Fatalf("len=%d want 12", len(b))
	}
	if b[0] != TString {
		t.Fatalf("type=%02x", b[0])
	}
	if got := binary.BigEndian.Uint32(b[3:7]); got != 5 {
		t.Fatalf("strLen=%d want 5", got)
	}
	if string(b[7:12]) != "hello" {
		t.Fatalf("value=%q want hello", b[7:12])
	}
}

func TestBuildFieldDouble(t *testing.T) {
	b, err := buildField(3, TDouble, core.ThriftField{Value: 3.14})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 11 {
		t.Fatalf("len=%d want 11 (type+id+8B)", len(b))
	}
	if b[0] != TDouble {
		t.Fatalf("type=%02x", b[0])
	}
	if got := binary.BigEndian.Uint16(b[1:3]); got != 3 {
		t.Fatalf("id=%d want 3", got)
	}
	// 3.14 as binary64 big-endian: 40091eb851eb851f
	want := "04000340091eb851eb851f"
	if hex(b) != want {
		t.Fatalf("hex=%s want %s", hex(b), want)
	}
}

func TestBuildFieldI64(t *testing.T) {
	b, err := buildField(0, TI64, core.ThriftField{Value: int64(10000000000)})
	if err != nil {
		t.Fatal(err)
	}
	// 10000000000 = 0x00000002540be400
	if got := binary.BigEndian.Uint64(b[3:11]); got != 10000000000 {
		t.Fatalf("value=%d want 10000000000", got)
	}
}

func TestBuildFieldI16(t *testing.T) {
	b, err := buildField(2, TI16, core.ThriftField{Value: int16(-42)})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 5 {
		t.Fatalf("len=%d want 5", len(b))
	}
	if got := binary.BigEndian.Uint16(b[3:5]); got != 0xffd6 {
		t.Fatalf("value=%04x want ffd6 (-42 as i16)", got)
	}
}

func TestBuildFieldByte(t *testing.T) {
	b, err := buildField(0, TByte, core.ThriftField{Value: 0x7f})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 4 {
		t.Fatalf("len=%d want 4", len(b))
	}
	if b[3] != 0x7f {
		t.Fatalf("value=%02x want 7f", b[3])
	}
}

func TestBuildFieldList(t *testing.T) {
	// LIST of I16 values [10, 20, 30]
	// encodeValue for TList currently uses TBool as default elem type
	// This tests the encoding path
	b, err := buildField(0, TList, core.ThriftField{Values: []interface{}{int64(10), int64(20), int64(30)}})
	if err != nil {
		t.Fatal(err)
	}
	// type(1) + id(2) + elemType(1) + count(4) + 3*1B (bool values) = 11
	if len(b) != 11 {
		t.Fatalf("len=%d want 11", len(b))
	}
	if b[0] != TList {
		t.Fatalf("type=%02x", b[0])
	}
}

// mapFieldFixture adapts the legacy map[string]interface{} fixture to the
// ThriftField entries form (declared STRING/I32).
func mapFieldFixture(m map[string]interface{}) core.ThriftField {
	f := core.ThriftField{KeyType: "STRING", ValueType: "I32"}
	for k, v := range m {
		f.Entries = append(f.Entries, core.ThriftMapEntry{Key: k, Value: v})
	}
	return f
}

func TestBuildFieldMap(t *testing.T) {
	m := map[string]interface{}{"key1": int64(100), "key2": int64(200)}
	b, err := buildField(0, TMap, mapFieldFixture(m))
	if err != nil {
		t.Fatal(err)
	}
	// type(1) + id(2) + keyType(1) + valType(1) + count(4) + entries
	if b[0] != TMap {
		t.Fatalf("type=%02x", b[0])
	}
	if b[3] != TString {
		t.Fatalf("keyType=%02x want %02x", b[3], TString)
	}
	if b[4] != TI32 {
		t.Fatalf("valType=%02x want %02x", b[4], TI32)
	}
	if got := binary.BigEndian.Uint32(b[5:9]); got != 2 {
		t.Fatalf("count=%d want 2", got)
	}
}

func TestBuildFieldSet(t *testing.T) {
	b, err := buildField(0, TSet, core.ThriftField{Values: []interface{}{int64(1), int64(2), int64(3)}})
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != TSet {
		t.Fatalf("type=%02x", b[0])
	}
}

func TestBuildFieldListEmpty(t *testing.T) {
	b, err := buildField(0, TList, core.ThriftField{Values: []interface{}{}})
	if err != nil {
		t.Fatal(err)
	}
	// type(1) + id(2) + elemType(1) + count(4) = 8
	if len(b) != 8 {
		t.Fatalf("len=%d want 8 (3 header + 5 list)", len(b))
	}
	if got := binary.BigEndian.Uint32(b[4:8]); got != 0 {
		t.Fatalf("count=%d want 0", got)
	}
}

func TestBuildFieldListOfStrings(t *testing.T) {
	// Even though default elem type is TBool, we can still exercise the code path
	// with a list of bool-convertible values
	b, err := buildField(0, TList, core.ThriftField{Values: []interface{}{true, false, true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 11 {
		t.Fatalf("len=%d want 11 (3 header + 3 list-header + 5 items)", len(b))
	}
	if b[3] != TBool {
		t.Fatalf("elemType=%02x want %02x", b[3], TBool)
	}
	if got := binary.BigEndian.Uint32(b[4:8]); got != 3 {
		t.Fatalf("count=%d want 3", got)
	}
}

func TestBuildMessageBodyCall(t *testing.T) {
	// CALL with two I32 args
	args := []core.ThriftField{
		{ID: 1, Type: "I32", Value: int64(1)},
		{ID: 2, Type: "I32", Value: int64(2)},
	}
	body, err := buildMessageBody(MCall, args, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 2 fields (7B each) + STOP = 15
	if len(body) != 15 {
		t.Fatalf("len=%d want 15", len(body))
	}
	if body[len(body)-1] != TStop {
		t.Fatalf("final byte=%02x want 00", body[len(body)-1])
	}
	// I32 field id=1 value=1
	if binary.BigEndian.Uint32(body[3:7]) != 1 {
		t.Fatalf("first field value=%d want 1", binary.BigEndian.Uint32(body[3:7]))
	}
}

func TestBuildMessageBodyReply(t *testing.T) {
	result := []core.ThriftField{
		{ID: 0, Type: "I32", Value: int64(3)},
	}
	body, err := buildMessageBody(MReply, nil, result, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 1 field (7B) + STOP = 8
	if len(body) != 8 {
		t.Fatalf("len=%d want 8", len(body))
	}
	if body[len(body)-1] != TStop {
		t.Fatalf("final byte=%02x want 00", body[len(body)-1])
	}
	if binary.BigEndian.Uint32(body[3:7]) != 3 {
		t.Fatalf("value=%d want 3", binary.BigEndian.Uint32(body[3:7]))
	}
}

func TestBuildMessageBodyException(t *testing.T) {
	exc := &core.ThriftException{Message: "division by zero", Type: 6}
	body, err := buildMessageBody(MException, nil, nil, exc)
	if err != nil {
		t.Fatal(err)
	}
	// STRING id=1 (12B) + I32 id=2 (7B) + STOP = 20
	if len(body) != 31 {
		t.Fatalf("len=%d want 31", len(body))
	}
	if body[len(body)-1] != TStop {
		t.Fatalf("final byte=%02x want 00", body[len(body)-1])
	}
}

func TestBuildMessageBodyExceptionNil(t *testing.T) {
	body, err := buildMessageBody(MException, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// STOP only = 1
	if len(body) != 1 || body[0] != TStop {
		t.Fatalf("body=%x want [00]", body)
	}
}

func TestBuildMessageBodyOneway(t *testing.T) {
	body, err := buildMessageBody(MOneway, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body[0] != TStop {
		t.Fatalf("body=%x want [00]", body)
	}
}

func TestAppendI16(t *testing.T) {
	b := appendI16(nil, 0x0102)
	if len(b) != 2 || b[0] != 0x01 || b[1] != 0x02 {
		t.Fatalf("appendI16=%x want 0102", b)
	}
}

func TestAppendI32(t *testing.T) {
	b := appendI32(nil, 0x01020304)
	want := "01020304"
	if hex(b) != want {
		t.Fatalf("hex=%s want %s", hex(b), want)
	}
}

func TestAppendI64(t *testing.T) {
	b := appendI64(nil, 0x0102030405060708)
	want := "0102030405060708"
	if hex(b) != want {
		t.Fatalf("hex=%s want %s", hex(b), want)
	}
}

func TestToInt(t *testing.T) {
	if got := toInt(42); got != 42 {
		t.Fatalf("toInt(42)=%d", got)
	}
	if got := toInt(int64(42)); got != 42 {
		t.Fatalf("toInt(int64(42))=%d", got)
	}
	if got := toInt(float64(42)); got != 42 {
		t.Fatalf("toInt(float64(42))=%d", got)
	}
	if got := toInt("abc"); got != 0 {
		t.Fatalf("toInt(string)=%d want 0", got)
	}
}

func TestToBool(t *testing.T) {
	if v, ok := toBool(true); !v || !ok {
		t.Fatalf("toBool(true)=%v,%v", v, ok)
	}
	if v, ok := toBool(false); v || !ok {
		t.Fatalf("toBool(false)=%v,%v", v, ok)
	}
	if v, ok := toBool("str"); ok {
		t.Fatalf("toBool(string) should fail, got=%v", v)
	}
}

func TestToFloat64(t *testing.T) {
	v, ok := toFloat64(3.14)
	if !ok || v != 3.14 {
		t.Fatalf("toFloat64(3.14)=%v,%v", v, ok)
	}
	v, ok = toFloat64(42)
	if !ok || v != 42.0 {
		t.Fatalf("toFloat64(42)=%v,%v", v, ok)
	}
	_, ok = toFloat64("str")
	if ok {
		t.Fatalf("toFloat64(string) should fail")
	}
}

func TestBuildFieldUnknownType(t *testing.T) {
	_, err := buildField(0, 0x01, core.ThriftField{})
	if err == nil {
		t.Fatalf("expected error for unknown type")
	}
}

func TestBuildFieldListDeclaredShape(t *testing.T) {
	// Container encoding is driven by declared metadata (Values), not the
	// Value shape; a bare Value is ignored and the declared empty list wins.
	b, err := buildField(0, TList, core.ThriftField{Value: "not an array", Values: []interface{}{int64(7)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 9 { // type+id+elemType+count(1)+i64 value(8)
		t.Fatalf("len=%d want 9", len(b))
	}
}

func TestBuildFieldMapDeclaredShape(t *testing.T) {
	f := core.ThriftField{Value: "not a map", KeyType: "STRING", ValueType: "I32",
		Entries: []core.ThriftMapEntry{{Key: "a", Value: 7}}}
	b, err := buildField(0, TMap, f)
	if err != nil {
		t.Fatal(err)
	}
	if b[3] != TString || b[4] != TI32 {
		t.Fatalf("key/val type=%02x/%02x want %02x/%02x", b[3], b[4], TString, TI32)
	}
	if got := binary.BigEndian.Uint32(b[5:9]); got != 1 {
		t.Fatalf("count=%d want 1", got)
	}
}

// --- Planner Validate tests ---

func TestValidateThriftAcceptsEmptyConfig(t *testing.T) {
	// P0b-2：空配置（Thrift nil）不再被 validator 拒绝——Generate/Plan 会默认化并产默认流。
	if err := (Planner{}).Validate(core.FlowSpec{}); err != nil {
		t.Fatalf("empty config should pass validation, got err=%v", err)
	}
}

func TestPlannerEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空配置（Thrift nil）→ Plan 默认化并产默认流。
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range ch {
		count++
	}
	if count < 4 {
		t.Fatalf("packets=%d want >=4", count)
	}
}

func TestValidateThriftMessagesRequired(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{Thrift: &core.ThriftConfig{}})
	if err == nil || !strings.Contains(err.Error(), "at least one message") {
		t.Fatalf("err=%v want at least one message", err)
	}
}

func TestValidateThriftInvalidMessageType(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{Thrift: &core.ThriftConfig{
		Messages: []core.ThriftMessage{
			{Type: "BOGUS", Method: "test"},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "invalid message type") {
		t.Fatalf("err=%v want invalid message type", err)
	}
}

func TestValidateThriftEmptyMethod(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{Thrift: &core.ThriftConfig{
		Messages: []core.ThriftMessage{
			{Type: "CALL", Method: ""},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "method is required") {
		t.Fatalf("err=%v want method is required", err)
	}
}

func TestValidateThriftUnknownFieldType(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{Thrift: &core.ThriftConfig{
		Messages: []core.ThriftMessage{
			{Type: "CALL", Method: "test", Args: []core.ThriftField{
				{ID: 1, Type: "UNKNOWN"},
			}},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "unknown field type") {
		t.Fatalf("err=%v want unknown field type", err)
	}
}

func TestValidateThriftBadIP(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Thrift: &core.ThriftConfig{
			Messages: []core.ThriftMessage{
				{Type: "CALL", Method: "test"},
			},
		},
		SrcIP: "not-an-ip",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Fatalf("err=%v want invalid source IP", err)
	}
}

func TestValidateThriftValid(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Thrift: &core.ThriftConfig{
			Messages: []core.ThriftMessage{
				{Type: "CALL", Method: "add", SeqID: 1,
					Args: []core.ThriftField{
						{ID: 1, Type: "I32", Value: int64(1)},
					}},
			},
		},
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Plan tests ---

func TestPlanThriftCallReply(t *testing.T) {
	// S1: CALL→REPLY, 9 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 9090,
		Count:   1,
		Thrift: &core.ThriftConfig{
			Messages: []core.ThriftMessage{
				{Type: "CALL", Method: "add", SeqID: 1,
					Args: []core.ThriftField{
						{ID: 1, Type: "I32", Value: int64(1)},
						{ID: 2, Type: "I32", Value: int64(2)},
					}},
				{Type: "REPLY", Method: "add", SeqID: 1,
					Result: []core.ThriftField{
						{ID: 0, Type: "I32", Value: int64(3)},
					}},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 9 {
		t.Fatalf("packet_count=%d want 9", len(packets))
	}
	// Check packet sequence
	// 0: SYN, 1: SYN-ACK, 2: ACK, 3: CALL data, 4: REPLY data, 5-8: FIN teardown
	if packets[0].L4.Flags != 0x02 {
		t.Fatalf("pkt[0] flags=%02x want SYN", packets[0].L4.Flags)
	}
	if packets[1].L4.Flags != 0x12 {
		t.Fatalf("pkt[1] flags=%02x want SYN-ACK", packets[1].L4.Flags)
	}
	if packets[2].L4.Flags != 0x10 {
		t.Fatalf("pkt[2] flags=%02x want ACK", packets[2].L4.Flags)
	}
	// pkt[3]: CALL up, direction=up, dest port 9090
	if packets[3].Direction != "up" {
		t.Fatalf("pkt[3] direction=%q want up", packets[3].Direction)
	}
	if packets[3].L4.DstPort != 9090 {
		t.Fatalf("pkt[3] dst_port=%d want 9090", packets[3].L4.DstPort)
	}
	// CALL payload: 30 bytes (version_type + nameLen + "add" + seqid + body)
	if len(packets[3].Payload) != 30 {
		t.Fatalf("CALL payload len=%d want 30", len(packets[3].Payload))
	}
	// Verify version_type = 0x80010001
	if got := binary.BigEndian.Uint32(packets[3].Payload[0:4]); got != 0x80010001 {
		t.Fatalf("CALL version_type=%08x want 80010001", got)
	}
	// pkt[4]: REPLY down
	if packets[4].Direction != "down" {
		t.Fatalf("pkt[4] direction=%q want down", packets[4].Direction)
	}
	if packets[4].L4.SrcPort != 9090 {
		t.Fatalf("pkt[4] src_port=%d want 9090", packets[4].L4.SrcPort)
	}
	// REPLY payload: 23 bytes
	if len(packets[4].Payload) != 23 {
		t.Fatalf("REPLY payload len=%d want 23", len(packets[4].Payload))
	}
	if got := binary.BigEndian.Uint32(packets[4].Payload[0:4]); got != 0x80010002 {
		t.Fatalf("REPLY version_type=%08x want 80010002", got)
	}
	// FIN teardown: pkt[5]=FIN/ACK(up), pkt[6]=ACK(down), pkt[7]=FIN/ACK(down), pkt[8]=ACK(up)
	if packets[5].L4.Flags != 0x11 {
		t.Fatalf("pkt[5] flags=%02x want FIN/ACK", packets[5].L4.Flags)
	}
	if packets[6].L4.Flags != 0x10 {
		t.Fatalf("pkt[6] flags=%02x want ACK", packets[6].L4.Flags)
	}
	if packets[7].L4.Flags != 0x11 {
		t.Fatalf("pkt[7] flags=%02x want FIN/ACK", packets[7].L4.Flags)
	}
	if packets[8].L4.Flags != 0x10 {
		t.Fatalf("pkt[8] flags=%02x want ACK", packets[8].L4.Flags)
	}
	// Verify canonical hex offset 54 (14 eth + 20 ip + 20 tcp)
	// CALL: 80010001 00000003 616464 00000001 08000100000001 08000200000002 00
	callWant := "800100010000000361646400000001080001000000010800020000000200"
	if hex(packets[3].Payload) != callWant {
		t.Fatalf("CALL payload hex=%s want %s", hex(packets[3].Payload), callWant)
	}
	replyWant := "8001000200000003616464000000010800000000000300"
	if hex(packets[4].Payload) != replyWant {
		t.Fatalf("REPLY payload hex=%s want %s", hex(packets[4].Payload), replyWant)
	}
}

func TestPlanThriftException(t *testing.T) {
	// S2: CALL→EXCEPTION, 9 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 9090,
		Count:   1,
		Thrift: &core.ThriftConfig{
			Messages: []core.ThriftMessage{
				{Type: "CALL", Method: "divide", SeqID: 7,
					Args: []core.ThriftField{
						{ID: 1, Type: "I32", Value: int64(1)},
						{ID: 2, Type: "I32", Value: int64(0)},
					}},
				{Type: "EXCEPTION", Method: "divide", SeqID: 7,
					Exception: &core.ThriftException{
						Message: "division by zero",
						Type:    6,
					}},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 9 {
		t.Fatalf("packet_count=%d want 9", len(packets))
	}
	// CALL payload: version_type=0x80010001 (CALL)
	if got := binary.BigEndian.Uint32(packets[3].Payload[0:4]); got != 0x80010001 {
		t.Fatalf("CALL version_type=%08x want 80010001", got)
	}
	// EXCEPTION payload: version_type=0x80010003
	if got := binary.BigEndian.Uint32(packets[4].Payload[0:4]); got != 0x80010003 {
		t.Fatalf("EXCEPTION version_type=%08x want 80010003", got)
	}
	if len(packets[4].Payload) != 49 {
		t.Fatalf("EXCEPTION payload len=%d want 49", len(packets[4].Payload))
	}
}

func TestPlanThriftOneway(t *testing.T) {
	// S3: ONEWAY, 8 packets (no response)
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 9090,
		Count:   1,
		Thrift: &core.ThriftConfig{
			Messages: []core.ThriftMessage{
				{Type: "ONEWAY", Method: "notify", SeqID: 42},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	// Only one data packet (ONEWAY up)
	if packets[3].Direction != "up" {
		t.Fatalf("pkt[3] direction=%q want up", packets[3].Direction)
	}
	if got := binary.BigEndian.Uint32(packets[3].Payload[0:4]); got != 0x80010004 {
		t.Fatalf("ONEWAY version_type=%08x want 80010004", got)
	}
	if len(packets[3].Payload) != 19 {
		t.Fatalf("ONEWAY payload len=%d want 19", len(packets[3].Payload))
	}
}

func TestPlanThriftDefaultPort(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
		Count: 1,
		Thrift: &core.ThriftConfig{
			Messages: []core.ThriftMessage{
				{Type: "ONEWAY", Method: "ping", SeqID: 1},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	if packets[3].L4.DstPort != 9090 {
		t.Fatalf("dst_port=%d want 9090 (default)", packets[3].L4.DstPort)
	}
}

func TestPlanThriftContainers(t *testing.T) {
	// S4: LIST/MAP/SET containers
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 9090,
		Count:   1,
		Thrift: &core.ThriftConfig{
			Messages: []core.ThriftMessage{
				{Type: "CALL", Method: "describe", SeqID: 1,
					Args: []core.ThriftField{
						{ID: 1, Type: "LIST", Value: []interface{}{int64(10), int64(20), int64(30)}},
						{ID: 2, Type: "MAP", Value: map[string]interface{}{"a": int64(1), "b": int64(2)}},
						{ID: 3, Type: "SET", Value: []interface{}{int64(100), int64(200)}},
					}},
				{Type: "REPLY", Method: "describe", SeqID: 1},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 9 {
		t.Fatalf("packet_count=%d want 9", len(packets))
	}
	// CALL should have container-encoded payload
	if len(packets[3].Payload) < 30 {
		t.Fatalf("CALL payload too short: %d", len(packets[3].Payload))
	}
}

func TestPlanThriftScalarTypes(t *testing.T) {
	// S5: all scalar types
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 9090,
		Count:   1,
		Thrift: &core.ThriftConfig{
			Messages: []core.ThriftMessage{
				{Type: "CALL", Method: "echo", SeqID: 1,
					Args: []core.ThriftField{
						{ID: 1, Type: "BOOL", Value: true},
						{ID: 2, Type: "BYTE", Value: int64(0x7f)},
						{ID: 3, Type: "DOUBLE", Value: 3.14},
						{ID: 4, Type: "I16", Value: int64(-42)},
						{ID: 5, Type: "I32", Value: int64(100000)},
						{ID: 6, Type: "I64", Value: int64(10000000000)},
						{ID: 7, Type: "STRING", Value: "hello"},
						{ID: 8, Type: "BINARY", Value: "raw"},
					}},
				{Type: "REPLY", Method: "echo", SeqID: 1},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 9 {
		t.Fatalf("packet_count=%d want 9", len(packets))
	}
	if len(packets[3].Payload) < 70 {
		t.Fatalf("CALL payload len=%d want >= 70", len(packets[3].Payload))
	}
}

func TestPlanThriftIPv6(t *testing.T) {
	// S6: IPv6
	spec := core.FlowSpec{
		SrcIP:   "2001:db8::1",
		DstIP:   "2001:db8::2",
		SrcPort: 12345,
		DstPort: 9090,
		Count:   1,
		Thrift: &core.ThriftConfig{
			Messages: []core.ThriftMessage{
				{Type: "CALL", Method: "echo", SeqID: 1,
					Args: []core.ThriftField{
						{ID: 1, Type: "I32", Value: int64(42)},
					}},
				{Type: "REPLY", Method: "echo", SeqID: 1,
					Result: []core.ThriftField{
						{ID: 0, Type: "I32", Value: int64(42)},
					}},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 9 {
		t.Fatalf("packet_count=%d want 9", len(packets))
	}
	// Check it's IPv6 (L3 should have IPv6 src)
	if packets[0].L3.SrcIP != "2001:db8::1" {
		t.Fatalf("pkt[0] src_ip=%q want 2001:db8::1", packets[0].L3.SrcIP)
	}
}

// --- Layer Generator tests ---

func TestThriftGeneratorName(t *testing.T) {
	g := &ThriftGenerator{}
	if g.Name() != "thrift" {
		t.Fatalf("Name=%q want thrift", g.Name())
	}
}

func TestThriftGeneratorGenerateCallReply(t *testing.T) {
	cfg := &core.ThriftConfig{
		Messages: []core.ThriftMessage{
			{Type: "CALL", Method: "add", SeqID: 1,
				Args: []core.ThriftField{
					{ID: 1, Type: "I32", Value: int64(1)},
					{ID: 2, Type: "I32", Value: int64(2)},
				}},
			{Type: "REPLY", Method: "add", SeqID: 1,
				Result: []core.ThriftField{
					{ID: 0, Type: "I32", Value: int64(3)},
				}},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{Thrift: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &ThriftGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2", len(events))
	}
	// First event: CALL up
	if !events[0].Up {
		t.Fatalf("event[0] Up=false want true")
	}
	if len(events[0].Bytes) != 30 {
		t.Fatalf("event[0] bytes=%d want 30", len(events[0].Bytes))
	}
	if got := binary.BigEndian.Uint32(events[0].Bytes[0:4]); got != 0x80010001 {
		t.Fatalf("event[0] version_type=%08x want 80010001", got)
	}
	// Second event: REPLY down
	if events[1].Up {
		t.Fatalf("event[1] Up=true want false")
	}
	if got := binary.BigEndian.Uint32(events[1].Bytes[0:4]); got != 0x80010002 {
		t.Fatalf("event[1] version_type=%08x want 80010002", got)
	}
}

func TestThriftGeneratorGenerateNilConfig(t *testing.T) {
	// P0b-2：空配置（Thrift nil）不再报错——Generate 默认化并产默认流。
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	}
	ctx := context.Background()
	g := &ThriftGenerator{}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("empty config should default, got err=%v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config produced no events")
	}
}

func TestThriftGeneratorGenerateNilReq(t *testing.T) {
	g := &ThriftGenerator{}
	err := g.Generate(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "EmitMsg is nil") {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestThriftGeneratorGenerateNilEmitMsg(t *testing.T) {
	req := &layers.GenRequest{Meta: layers.FlowMeta{}}
	g := &ThriftGenerator{}
	err := g.Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "EmitMsg is nil") {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestThriftGeneratorGenerateContextCancel(t *testing.T) {
	cfg := &core.ThriftConfig{
		Messages: []core.ThriftMessage{
			{Type: "CALL", Method: "add", SeqID: 1},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{Thrift: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	g := &ThriftGenerator{}
	err := g.Generate(ctx, req)
	if err == nil {
		t.Fatalf("expected context error")
	}
}

func TestThriftRegister(t *testing.T) {
	// Verify layer generator is registered
	gen, err := layers.NewLayerGenerator("thrift")
	if err != nil {
		t.Fatalf("NewLayerGenerator(thrift): %v", err)
	}
	if gen == nil {
		t.Fatalf("generator is nil")
	}
	if gen.Name() != "thrift" {
		t.Fatalf("name=%q want thrift", gen.Name())
	}
}

// --- Helper ---

func collectPackets(ch <-chan core.PacketConfig, max int) []core.PacketConfig {
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
		if len(pkts) >= max {
			break
		}
	}
	return pkts
}
// --- Case-derived tests (T3 batch 3): auto-REPLY, type_code/wire_fault
// rejection, container encoding from declared metadata ---

func TestGenerateAutoReplyForUnmatchedCall(t *testing.T) {
	// case thrift_containers/scalar_types: CALL without explicit response ->
	// auto empty REPLY (9 packets: 3 hs + 2 payload + 4 teardown in Plan path).
	var events []layers.MessageEvent
	err := (&ThriftGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{Thrift: &core.ThriftConfig{Messages: []core.ThriftMessage{
			{Type: "CALL", Method: "ping", SeqID: 1},
		}}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2 (CALL + auto REPLY)", len(events))
	}
	if events[0].Up != true || events[1].Up != false {
		t.Fatalf("directions=%v/%v want up/down", events[0].Up, events[1].Up)
	}
	// auto REPLY: version_type low byte 02, same method/seqid, body STOP only
	if got := binary.BigEndian.Uint32(events[1].Bytes[0:4]); got != 0x80010002 {
		t.Fatalf("reply version_type=%08x want 80010002", got)
	}
	if got := binary.BigEndian.Uint32(events[1].Bytes[12:16]); got != 1 {
		t.Fatalf("reply seqid=%d want 1", got)
	}
	if len(events[1].Bytes) != 17 { // 12 header + 4 name + 1 STOP
		t.Fatalf("reply len=%d want 17", len(events[1].Bytes))
	}
}

func TestGenerateNoAutoReplyForExplicitResponse(t *testing.T) {
	// case thrift_call_reply: CALL + explicit REPLY -> no extra events.
	var events []layers.MessageEvent
	err := (&ThriftGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{Thrift: &core.ThriftConfig{Messages: []core.ThriftMessage{
			{Type: "CALL", Method: "add", SeqID: 1, Args: []core.ThriftField{{ID: 1, Type: "I32", Value: 1}}},
			{Type: "REPLY", Method: "add", SeqID: 1, Result: []core.ThriftField{{ID: 0, Type: "I32", Value: 3}}},
		}}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2 (no auto reply)", len(events))
	}
}

func TestGenerateNoAutoReplyForOneway(t *testing.T) {
	// case thrift_oneway_call: ONEWAY is fire-and-forget -> single event.
	var events []layers.MessageEvent
	err := (&ThriftGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{Thrift: &core.ThriftConfig{Messages: []core.ThriftMessage{
			{Type: "ONEWAY", Method: "notify", SeqID: 4},
		}}},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1 (oneway has no response)", len(events))
	}
}

func TestValidateRejectsBadMessageTypeCode(t *testing.T) {
	// case thrift_neg_bad_message_type: type_code 9 must be rejected with the
	// case's error_contains anchor "invalid message type".
	err := (Planner{}).Validate(core.FlowSpec{Thrift: &core.ThriftConfig{Messages: []core.ThriftMessage{
		{TypeCode: 9, Method: "bad", SeqID: 1},
	}}})
	if err == nil || !strings.Contains(err.Error(), "invalid message type") {
		t.Fatalf("err=%v want 'invalid message type'", err)
	}
}

func TestValidateRejectsUnknownFieldTypeCode(t *testing.T) {
	// case thrift_neg_unknown_type: field type_code 99 rejected with anchor
	// "unknown field type".
	err := (Planner{}).Validate(core.FlowSpec{Thrift: &core.ThriftConfig{Messages: []core.ThriftMessage{
		{Type: "CALL", Method: "bad", SeqID: 1, Args: []core.ThriftField{{ID: 1, TypeCode: 99}}},
	}}})
	if err == nil || !strings.Contains(err.Error(), "unknown field type") {
		t.Fatalf("err=%v want 'unknown field type'", err)
	}
}

func TestValidateRejectsWireFaults(t *testing.T) {
	// cases thrift_neg_truncated / _negative_length / _negative_container_count
	tests := []struct {
		wf   core.ThriftWireFault
		want string
	}{
		{core.ThriftWireFault{Kind: "truncate", At: "string_bytes"}, "truncated"},
		{core.ThriftWireFault{Kind: "negative_length", FieldID: 1}, "negative length"},
		{core.ThriftWireFault{Kind: "negative_container_count", FieldID: 1}, "negative container count"},
	}
	for _, tc := range tests {
		err := (Planner{}).Validate(core.FlowSpec{Thrift: &core.ThriftConfig{
			Messages:  []core.ThriftMessage{{Type: "CALL", Method: "x", SeqID: 1}},
			WireFault: &tc.wf,
		}})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("wf %+v: err=%v want %q", tc.wf, err, tc.want)
		}
	}
}

func TestBuildFieldContainersFromDeclaredMetadata(t *testing.T) {
	// case thrift_containers: LIST(I16)[1,-2] / MAP(STRING,I32){a:7} / SET(STRING)[x,y]
	lst, err := buildField(1, TList, core.ThriftField{ElemType: "I16", Values: []interface{}{1, -2}})
	if err != nil {
		t.Fatal(err)
	}
	want := "0f000106000000020001fffe" // LIST id=1 elem=I16 count=2 [1, -2]
	if hex(lst) != want {
		t.Fatalf("list hex=%s want %s", hex(lst), want)
	}
	mp, err := buildField(2, TMap, core.ThriftField{KeyType: "STRING", ValueType: "I32",
		Entries: []core.ThriftMapEntry{{Key: "a", Value: 7}}})
	if err != nil {
		t.Fatal(err)
	}
	want = "0d00020d080000000100000001610000000 7"
	want = "0d00020b0800000001000000016100000007" // MAP id=2 kt=STRING vt=I32 count=1 "a"=7
	if hex(mp) != want {
		t.Fatalf("map hex=%s want %s", hex(mp), want)
	}
	st, err := buildField(3, TSet, core.ThriftField{ElemType: "STRING", Values: []interface{}{"x", "y"}})
	if err != nil {
		t.Fatal(err)
	}
	want = "0e00030b000000020000000178000000017 9"
	want = "0e00030b0000000200000001780000000179" // SET id=3 elem=STRING count=2 x,y
	if hex(st) != want {
		t.Fatalf("set hex=%s want %s", hex(st), want)
	}
}

func TestBuildFieldBinaryFromB64(t *testing.T) {
	// case thrift_scalar_types: BINARY value_b64 "AP8=" -> bytes 0x00 0xff
	b, err := buildField(8, TString, core.ThriftField{ValueB64: []byte{0x00, 0xff}})
	if err != nil {
		t.Fatal(err)
	}
	want := "0b00080000000200ff" // STRING id=8 len=2 00 ff
	if hex(b) != want {
		t.Fatalf("hex=%s want %s", hex(b), want)
	}
}

func TestPlanScalarTypesPacketCount(t *testing.T) {
	// case thrift_scalar_types end-to-end: CALL(8 scalar fields) -> 9 packets.
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9090,
		Thrift: &core.ThriftConfig{Messages: []core.ThriftMessage{
			{Type: "CALL", Method: "scalars", SeqID: 1, Args: []core.ThriftField{
				{ID: 1, Type: "BOOL", Value: true},
				{ID: 2, Type: "BYTE", Value: -1},
				{ID: 3, Type: "DOUBLE", Value: 3.5},
				{ID: 4, Type: "I16", Value: -2},
				{ID: 5, Type: "I32", Value: -3},
				{ID: 6, Type: "I64", Value: -4},
				{ID: 7, Type: "STRING", Value: "x"},
				{ID: 8, Type: "BINARY", ValueB64: []byte{0x00, 0xff}},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 9 {
		t.Fatalf("packets=%d want 9", n)
	}
}
