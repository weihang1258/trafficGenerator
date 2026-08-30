package mms

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func tpkt(body []byte) ([]byte, error) {
	if len(body) > 65531 {
		return nil, fmt.Errorf("mms: TPKT body exceeds 65531 bytes")
	}
	out := make([]byte, 4+len(body))
	out[0], out[1] = 3, 0
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	copy(out[4:], body)
	return out, nil
}

func BuildCR() ([]byte, error) {
	return tpkt([]byte{0x0f, 0xe0, 0, 0, 0, 1, 0, 0xc0, 1, 0x0c, 0xc2, 1, 1, 0xc1, 1, 2})
}
func BuildCC() ([]byte, error) {
	return tpkt([]byte{0x0f, 0xd0, 0, 1, 0, 2, 0, 0xc0, 1, 0x0c, 0xc1, 1, 1, 0xc2, 1, 2})
}

func cotpDT(data []byte) ([]byte, error) {
	body := append([]byte{2, 0xf0, 0x80}, data...)
	return tpkt(body)
}

func ber(tag byte, value []byte) []byte {
	out := []byte{tag}
	if len(value) < 128 {
		out = append(out, byte(len(value)))
	} else {
		length := len(value)
		var encoded [4]byte
		i := len(encoded)
		for length > 0 {
			i--
			encoded[i] = byte(length)
			length >>= 8
		}
		count := len(encoded) - i
		out = append(out, 0x80|byte(count))
		out = append(out, encoded[i:]...)
	}
	return append(out, value...)
}
func seq(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// variableAccessSpecification encodes the MMS VariableAccessSpecification
// CHOICE as listOfVariable: a1 wrapper (VAS [1]) + a0 (listOfVariable [0])
// + one universal SEQUENCE (0x30) item per variable. Domain/item ids are
// universal VisibleString (0x1a) — tshark 3.6.14 packet-mms.c requires
// BER_UNI_TAG_VisibleString for T_domain_specific (context tags 0x8a decode
// as a dissector error).
func variableAccessSpecification(cfg *MMSConfig) []byte {
	var items []byte
	for _, obj := range cfg.Objects {
		name := ber(0xa0, ber(0xa1, seq(ber(0x1a, []byte(obj.Domain)), ber(0x1a, []byte(obj.Name)))))
		items = append(items, ber(0x30, name)...)
	}
	return ber(0xa1, ber(0xa0, items))
}

func dataValue(obj MMSObjectConfig) []byte {
	switch obj.Datatype {
	case "boolean":
		if v, ok := obj.Value.(bool); ok && v {
			return ber(0x83, []byte{0xff})
		}
		return ber(0x83, []byte{0})
	case "integer":
		return ber(0x85, integerBytes(obj.Value))
	case "unsigned":
		return ber(0x86, integerBytes(obj.Value))
	case "octetString":
		return ber(0x89, octetBytes(obj.Value))
	case "utcTime":
		// IEC 61850 UtcTime = 8 bytes (4B seconds BE + 3B fraction + 1B
		// quality); tshark flags any other length as malformed.
		sec := uint32(0)
		if v, ok := obj.Value.(int); ok {
			sec = uint32(v)
		} else if v, ok := obj.Value.(float64); ok {
			sec = uint32(v)
		}
		content := make([]byte, 8)
		binary.BigEndian.PutUint32(content[0:4], sec)
		return ber(0x91, content)
	case "visibleString":
		return ber(0x8a, []byte(fmt.Sprint(obj.Value)))
	default:
		return ber(0x80, nil)
	}
}

func integerBytes(v interface{}) []byte {
	var n int64
	switch x := v.(type) {
	case int:
		n = int64(x)
	case int8:
		n = int64(x)
	case int16:
		n = int64(x)
	case int32:
		n = int64(x)
	case int64:
		n = x
	case uint:
		n = int64(x)
	case uint8:
		n = int64(x)
	case uint16:
		n = int64(x)
	case uint32:
		n = int64(x)
	case uint64:
		n = int64(x)
	case float64:
		n = int64(x)
	default:
		return []byte{0}
	}
	if n == 0 {
		return []byte{0}
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n)}, out...)
		n >>= 8
	}
	if negative {
		for i := range out {
			out[i] = ^out[i]
		}
		for i := len(out) - 1; i >= 0; i-- {
			out[i]++
			if out[i] != 0 {
				break
			}
		}
	}
	if !negative && out[0]&0x80 != 0 {
		out = append([]byte{0}, out...)
	}
	if negative && out[0]&0x80 == 0 {
		out = append([]byte{0xff}, out...)
	}
	return out
}

func octetBytes(v interface{}) []byte {
	s := fmt.Sprint(v)
	if len(s)%2 == 0 {
		out := make([]byte, len(s)/2)
		valid := true
		for i := range out {
			var hi, lo byte
			if s[2*i] >= '0' && s[2*i] <= '9' {
				hi = s[2*i] - '0'
			} else if s[2*i] >= 'a' && s[2*i] <= 'f' {
				hi = s[2*i] - 'a' + 10
			} else if s[2*i] >= 'A' && s[2*i] <= 'F' {
				hi = s[2*i] - 'A' + 10
			} else {
				valid = false
			}
			if s[2*i+1] >= '0' && s[2*i+1] <= '9' {
				lo = s[2*i+1] - '0'
			} else if s[2*i+1] >= 'a' && s[2*i+1] <= 'f' {
				lo = s[2*i+1] - 'a' + 10
			} else if s[2*i+1] >= 'A' && s[2*i+1] <= 'F' {
				lo = s[2*i+1] - 'A' + 10
			} else {
				valid = false
			}
			out[i] = hi<<4 | lo
		}
		if valid {
			return out
		}
	}
	return []byte(s)
}

// confirmedRequest wraps a service request body into the top-level
// Confirmed-RequestPDU (invokeID is a universal INTEGER, no own tag —
// packet-mms.c Confirmed_RequestPDU_sequence BER_FLAGS_NOOWNTAG).
func confirmedRequest(invoke byte, service []byte) []byte {
	return ber(0xa0, seq(ber(0x02, []byte{invoke}), service))
}

// confirmedResponse wraps a service response body into the top-level
// Confirmed-ResponsePDU (invokeID is a universal INTEGER, no own tag).
func confirmedResponse(invoke byte, service []byte) []byte {
	return ber(0xa1, seq(ber(0x02, []byte{invoke}), service))
}

func BuildReadRequest(cfg *MMSConfig, invoke byte) ([]byte, error) {
	return confirmedRequest(invoke, ber(0xa4, variableAccessSpecification(cfg))), nil
}

func BuildReadResponse(cfg *MMSConfig, invoke byte) ([]byte, error) {
	var values []byte
	if cfg != nil {
		for _, obj := range cfg.Objects {
			values = append(values, dataValue(obj)...)
		}
	}
	// Read-Response [4] = { listOfAccessResult [1] IMPLICIT SEQUENCE OF
	// AccessResult } — items are raw Data tags (no per-item wrapper).
	return confirmedResponse(invoke, ber(0xa4, ber(0xa1, values))), nil
}

func BuildWriteRequest(cfg *MMSConfig, invoke byte) ([]byte, error) {
	var values []byte
	if cfg != nil {
		for _, obj := range cfg.Objects {
			values = append(values, dataValue(obj)...)
		}
	}
	// Write-Request [5] = { variableAccessSpecification (any tag),
	// listOfData [0] IMPLICIT SEQUENCE OF Data }.
	return confirmedRequest(invoke, ber(0xa5, seq(variableAccessSpecification(cfg), ber(0xa0, values)))), nil
}

func BuildWriteResponse(cfg *MMSConfig, invoke byte) ([]byte, error) {
	var results []byte
	if cfg != nil {
		for range cfg.Objects {
			// Write-Response item CHOICE: success [1] IMPLICIT NULL.
			results = append(results, ber(0x81, nil)...)
		}
	}
	// Write-Response [5] IMPLICIT SEQUENCE OF item — items carry their own
	// choice tags, no wrapper.
	return confirmedResponse(invoke, ber(0xa5, results)), nil
}

func BuildGetNameListRequest(invoke byte) ([]byte, error) {
	// GetNameList-Request [1] = { extendedObjectClass [0] EXPLICIT CHOICE
	// {objectClass [0] IMPL INTEGER}, objectScope [1] (vmdSpecific [0]
	// IMPLICIT NULL inside — tshark 3.6 enforces the objectScope field tag,
	// a bare 80 00 trips "expected tag 1" malformed) }.
	extended := ber(0xa0, ber(0x80, []byte{0x00}))
	scope := ber(0xa1, ber(0x80, nil))
	return confirmedRequest(invoke, ber(0xa1, seq(extended, scope))), nil
}

func BuildGetNameListResponse(cfg *MMSConfig, invoke byte) ([]byte, error) {
	var names []byte
	if cfg != nil {
		for _, obj := range cfg.Objects {
			// listOfIdentifier items are universal VisibleString.
			names = append(names, ber(0x1a, []byte(obj.Name))...)
		}
	}
	return confirmedResponse(invoke, ber(0xa1, ber(0xa0, names))), nil
}

func BuildIdentifyRequest(invoke byte) ([]byte, error) {
	return ber(0xa0, seq(ber(0x02, []byte{invoke}), ber(0xa2, nil))), nil
}

func BuildIdentifyResponse(cfg *MMSConfig, invoke byte) ([]byte, error) {
	vendor := "FAKE8150"
	if cfg != nil && cfg.IEDName != "" {
		vendor = cfg.IEDName
	}
	body := seq(ber(0x02, []byte{invoke}), ber(0xa2, seq(ber(0x80, []byte(vendor)), ber(0x81, []byte("MMS")), ber(0x82, []byte("1.0")))))
	return ber(0xa1, body), nil
}

func BuildInformationReport(cfg *MMSConfig) ([]byte, error) {
	var values []byte
	if cfg != nil {
		for _, obj := range cfg.Objects {
			values = append(values, dataValue(obj)...)
		}
	}
	// Unconfirmed-PDU [3] = { informationReport [0] IMPLICIT
	// SEQUENCE { variableAccessSpecification (any tag), listOfAccessResult
	// [0] IMPLICIT SEQUENCE OF Data } }.
	return ber(0xa3, ber(0xa0, seq(variableAccessSpecification(cfg), ber(0xa0, values)))), nil
}

func BuildServiceError(cfg *MMSConfig, invoke byte) ([]byte, error) {
	value := 2
	if cfg != nil && cfg.ErrorValue != 0 {
		value = cfg.ErrorValue
	}
	classTag := byte(0x87)
	if cfg != nil {
		switch cfg.ErrorClassName {
		case "definition":
			classTag = 0x82
		case "service":
			classTag = 0x84
		}
	}
	// Confirmed-ErrorPDU [2] SEQUENCE: invokeID [0] IMPLICIT (context tag,
	// unlike the universal invokeID of request/response PDUs — packet-mms.c
	// Confirmed_ErrorPDU_sequence BER_FLAGS_IMPLTAG), serviceError [2]
	// EXPLICIT { errorClass [0] EXPLICIT { <class tag> <value> } }.
	errorDetail := ber(0xa0, ber(classTag, integerBytes(value)))
	serviceError := ber(0xa2, errorDetail)
	return ber(0xa2, seq(ber(0x80, []byte{invoke}), serviceError)), nil
}

// spduParams is the fixed 23-byte session parameter block (version /
// token / activity descriptors) shared by CR and CC DT payloads.
var spduParams = []byte{0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, 0x14, 0x02, 0x00, 0x02, 0x33, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x34, 0x02, 0x00, 0x01}

// BuildAssociate encodes the MMS Initiate carried in an ACSE association
// (request: AARQ, response: ABRP) wrapped in the session CP/CPA SPDU and a
// COTP DT TPDU. With default parameters the output is byte-identical to the
// reference captures (request 165 B, response 161 B — unit-tested). The
// request envelope uses the marker + 2-byte length form (c1 81 <len16>) and
// the response the raw single-byte LI (c1 <len>) form of the reference
// captures; the SPDU LI is len(CP content) + 19, matching the captures.
func BuildAssociate(cfg *MMSConfig, response bool) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("mms: config is nil")
	}
	a := cfg.Association
	local := uint32(64000)
	calling, called, nesting := byte(5), byte(5), byte(10)
	if a != nil {
		if a.LocalDetail != 0 {
			local = a.LocalDetail
		}
		if a.MaxOutstandingCalling != 0 {
			calling = a.MaxOutstandingCalling
		}
		if a.MaxOutstandingCalled != 0 {
			called = a.MaxOutstandingCalled
		}
		if a.NestingLevel != 0 {
			nesting = a.NestingLevel
		}
	}
	var services []byte
	if a != nil && a.ServicesSupported != "" {
		decoded, err := hex.DecodeString(a.ServicesSupported)
		if err != nil || len(decoded) == 0 || decoded[0] > 7 {
			return nil, fmt.Errorf("mms: invalid servicesSupported bit string")
		}
		if decoded[0] != 0 && decoded[len(decoded)-1]&((byte(1)<<decoded[0])-1) != 0 {
			return nil, fmt.Errorf("mms: invalid servicesSupported bit string")
		}
		services = decoded
	} else if response {
		services = []byte{0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	} else {
		services = []byte{5, 0xee, 0x1c, 0, 0, 4, 8, 0, 0, 0x79, 0xef, 0x18}
	}

	// ACSE initiate (a8 request / a9 response) with calling/called detail and
	// the ACSE version + services-supported element (a4).
	detail := seq([]byte{0x80, 4},
		[]byte{byte(local >> 24), byte(local >> 16), byte(local >> 8), byte(local)},
		[]byte{0x81, 1, calling}, []byte{0x82, 1, called}, []byte{0x83, 1, nesting})
	ver := []byte{5, 0xf1, 0}
	if response {
		ver = []byte{5, 0xf1}
	}
	detail = seq(detail, ber(0xa4, seq([]byte{0x80, 1, 1}, ber(0x81, ver), ber(0x82, services))))
	initiate := ber(map[bool]byte{false: 0xa8, true: 0xa9}[response], detail)

	// EXTERNAL encoded MMS payload (be → 28 → 02 01 03 + a0 → initiate).
	ext := ber(0xbe, ber(0x28, seq([]byte{2, 1, 3}, ber(0xa0, initiate))))
	inner := ber(0xa1, []byte{6, 0x28, 0xca, 0x22, 2, 3})
	if response {
		inner = seq(inner, ber(0xa2, []byte{2, 1, 0}), ber(0xa3, []byte{0xa1, 3, 2, 1, 0}))
	}
	inner = seq(inner, ext)
	acse := ber(map[bool]byte{false: 0x60, true: 0x61}[response], inner)
	// Fully-encoded ACSE wrapped as 61 { 30 { 02 01 01, a0 { acse } } }.
	acseWrapped := ber(0x61, ber(0x30, seq([]byte{2, 1, 1}, ber(0xa0, acse))))

	var a2content []byte
	if response {
		// CPA: accepted proposal (83 04 00000001) + result list (a5: two
		// 30 0d items) + wrapped ACSE.
		item := func(v byte) []byte {
			return ber(0x30, seq([]byte{2, 2, 1, v}, ber(0x30, []byte{0x80, 1, 0, 0x81, 2, 0x51, 1})))
		}
		a2content = seq(ber(0x83, []byte{0, 0, 0, 1}), ber(0xa5, seq(item(1), item(3))), acseWrapped)
	} else {
		// CP: protocol options (81/82 4-byte constants) + calling/called
		// presentation selector list (a4: two 30 items) + wrapped ACSE.
		item1 := ber(0x30, seq([]byte{2, 2, 1, 1, 6, 4, 0x52, 1, 0, 1}, ber(0x30, []byte{6, 2, 0x51, 1})))
		item3 := ber(0x30, seq([]byte{2, 2, 1, 3, 6, 5, 0x28, 0xca, 0x22, 2, 1}, ber(0x30, []byte{6, 2, 0x51, 1})))
		a2content = seq(ber(0x81, []byte{0x12, 0x34, 0x56, 0x78}), ber(0x82, []byte{0x87, 0x65, 0x43, 0x21}),
			ber(0xa4, seq(item1, item3)), acseWrapped)
	}
	cpContent := seq([]byte{0xa0, 3, 0x80, 1, 1}, ber(0xa2, a2content))
	cp := ber(0x31, cpContent)

	var body []byte
	if response {
		if len(cp) < 255 {
			body = seq([]byte{0xc1, byte(len(cp))}, cp)
		} else {
			body = seq([]byte{0xc1, 0xff, byte(len(cp) >> 8), byte(len(cp))}, cp)
		}
	} else {
		if len(cp) > 0xffff {
			return nil, fmt.Errorf("mms: TPKT body exceeds 65531 bytes")
		}
		body = seq([]byte{0xc1, 0x81, byte(len(cp) >> 8), byte(len(cp))}, cp)
	}
	li := len(cpContent) + 19
	var liBytes []byte
	if li < 255 {
		liBytes = []byte{byte(li)}
	} else {
		liBytes = []byte{0xff, byte(li >> 8), byte(li)}
	}
	session := seq([]byte{map[bool]byte{false: 0x0d, true: 0x0e}[response]}, liBytes, spduParams, body)
	return cotpDT(session)
}
