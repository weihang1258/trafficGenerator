package modbus

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// FC 0x08 with config "data" field: DataField bytes follow SubFunction in the
// request; sub-function 0x0000 response echoes the request (§3.3.6).
func TestFC08DataFieldEcho(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0000,
		Data:         []byte{0xA5, 0x37},
	}
	req := buildDiagnosticRequest(op)
	wantReq := []byte{0x08, 0x00, 0x00, 0xA5, 0x37}
	if string(req) != string(wantReq) {
		t.Fatalf("request = %x, want %x", req, wantReq)
	}
	resp := buildDiagnosticResponse(op)
	if string(resp) != string(wantReq) {
		t.Fatalf("response echo = %x, want %x", resp, wantReq)
	}
}

// FC 0x08 falls back to legacy Values when Data absent (regression guard).
func TestFC08ValuesFallback(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x08,
		SubFunction:  0x0001,
		Values:       []byte{0xFF, 0xFF},
	}
	req := buildDiagnosticRequest(op)
	want := []byte{0x08, 0x00, 0x01, 0xFF, 0xFF}
	if string(req) != string(want) {
		t.Fatalf("request = %x, want %x", req, want)
	}
}

// FC 0x2B MEI response from mei_objects + conformity_level config fields:
// MEI Type=0x0E + Code=0x01 + Conformity + More=0 + Next=0 + Count +
// objects (ID + Len + Value) (§3.3.17).
func TestFC2BMEIObjectsResponse(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x2B,
		SubFunction:     0x000E,
		ConformityLevel: 0x02,
		MEIObjects: []core.MODBUSMEIObject{
			{ObjectID: 0, ObjectValue: "TrafficGen"},
		},
	}
	resp := buildMEIResponse(op)
	// FC is prepended by buildResponsePDU wrapper? No: buildMEIResponse returns
	// bytes starting at MEI Type when ResponseValues path used FC prefix; the
	// objects path must match the same convention: check actual layout.
	want := []byte{
		0x2B,       // FC
		0x0E,       // MEI Type
		0x01,       // Read Device ID Code (Basic)
		0x02,       // Conformity
		0x00, 0x00, // More Follows, Next Object ID
		0x01,                         // Object Count
		0x00, 0x0A,                   // Object ID, Length("TrafficGen")=10
		'T', 'r', 'a', 'f', 'f', 'i', 'c', 'G', 'e', 'n',
	}
	if string(resp) != string(want) {
		t.Fatalf("response = %x, want %x", resp, want)
	}
}

// ConformityLevel absent → default 0x01 (Basic Identification, §3.3.17).
func TestFC2BMEIConformityDefault(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode: 0x2B,
		SubFunction:  0x000E,
		MEIObjects: []core.MODBUSMEIObject{
			{ObjectID: 1, ObjectValue: "v1"},
		},
	}
	resp := buildMEIResponse(op)
	if len(resp) < 4 || resp[3] != 0x01 {
		t.Fatalf("conformity byte = %v, want 0x01", resp)
	}
	if resp[6] != 0x01 || resp[7] != 0x01 {
		t.Fatalf("object id/len = %x, want id=1 len=2", resp[6:9])
	}
}

// MEI request defaults: Read Device ID Code = ConformityLevel (0x01 when
// absent), Object ID = StartingAddress (T-204 / mei-read-device-id pins).
func TestFC2BMEIRequestDefaults(t *testing.T) {
	op := &core.MODBUSOperation{
		FunctionCode:    0x2B,
		SubFunction:     0x000E,
		ConformityLevel: 2,
		StartingAddress: 0,
	}
	req := buildMEIRequest(op)
	want := []byte{0x2B, 0x0E, 0x02, 0x00}
	if string(req) != string(want) {
		t.Fatalf("request = %x, want %x", req, want)
	}

	op.StartingAddress = 1
	op.ConformityLevel = 0
	req = buildMEIRequest(op)
	want = []byte{0x2B, 0x0E, 0x01, 0x01}
	if string(req) != string(want) {
		t.Fatalf("request = %x, want %x", req, want)
	}
}

// 评审 LOW：flat 路径（strategy_convert mapToFlowSpec）必须同参携带
// data/mei_objects/conformity_level——层链与 flat 同配同线。
func TestFlatPathDataAndMEIParity(t *testing.T) {
	cfg := map[string]interface{}{
		"modbus": map[string]interface{}{
			"transactions": []interface{}{
				map[string]interface{}{
					"function_code":    float64(8),
					"sub_function":     float64(0),
					"data":             []interface{}{float64(0xA5), float64(0x37)},
					"conformity_level": float64(2),
					"mei_objects": []interface{}{
						map[string]interface{}{"object_id": float64(0), "object_value": "TG"},
					},
				},
			},
		},
	}
	spec := core.ConvertFlatSpec(cfg, "modbus")
	if len(spec.MODBUS.Transactions) != 1 {
		t.Fatalf("transactions = %d, want 1", len(spec.MODBUS.Transactions))
	}
	op := spec.MODBUS.Transactions[0]
	if string(op.Data) != string([]byte{0xA5, 0x37}) {
		t.Fatalf("op.Data = %x, want a537", op.Data)
	}
	if op.ConformityLevel != 2 {
		t.Fatalf("op.ConformityLevel = %d, want 2", op.ConformityLevel)
	}
	if len(op.MEIObjects) != 1 || op.MEIObjects[0].ObjectID != 0 || op.MEIObjects[0].ObjectValue != "TG" {
		t.Fatalf("op.MEIObjects = %+v, want [{0 TG}]", op.MEIObjects)
	}
}
