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

func encodeLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var tmp [4]byte
	i := len(tmp)
	for v := n; v > 0; {
		i--
		tmp[i] = byte(v)
		v >>= 8
	}
	count := len(tmp) - i
	return append([]byte{0x80 | byte(count)}, tmp[i:]...)
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

func variableSpecification(cfg *MMSConfig) []byte {
	var vars []byte
	if cfg == nil {
		return ber(0xa1, ber(0xa0, nil))
	}
	for _, obj := range cfg.Objects {
		name := ber(0xa1, seq(ber(0x8a, []byte(obj.Domain)), ber(0x8a, []byte(obj.Name))))
		vars = append(vars, ber(0xa0, name)...)
	}
	return ber(0xa1, ber(0xa0, vars))
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
		return ber(0x91, integerBytes(obj.Value))
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

func BuildReadRequest(cfg *MMSConfig, invoke byte) ([]byte, error) {
	return ber(0xa0, seq(ber(0x02, []byte{invoke}), ber(0xa4, seq(ber(0x80, []byte{0}), variableSpecification(cfg))))), nil
}

func BuildReadResponse(cfg *MMSConfig, invoke byte) ([]byte, error) {
	var values []byte
	if cfg != nil {
		for _, obj := range cfg.Objects {
			values = append(values, dataValue(obj)...)
		}
	}
	return ber(0xa1, seq(ber(0x02, []byte{invoke}), ber(0xa4, ber(0xa1, values)))), nil
}

func BuildWriteRequest(cfg *MMSConfig, invoke byte) ([]byte, error) {
	var values []byte
	if cfg != nil {
		for _, obj := range cfg.Objects {
			values = append(values, dataValue(obj)...)
		}
	}
	return ber(0xa0, seq(ber(0x02, []byte{invoke}), ber(0xa5, seq(variableSpecification(cfg), ber(0xa0, values))))), nil
}

func BuildWriteResponse(cfg *MMSConfig, invoke byte) ([]byte, error) {
	var results []byte
	if cfg != nil {
		for range cfg.Objects {
			results = append(results, ber(0x80, []byte{0})...)
		}
	}
	return ber(0xa1, seq(ber(0x02, []byte{invoke}), ber(0xa5, ber(0xa0, results)))), nil
}

func BuildGetNameListRequest(invoke byte) ([]byte, error) {
	body := seq(ber(0x80, nil), ber(0xa1, ber(0x80, nil)))
	return ber(0xa0, seq(ber(0x02, []byte{invoke}), ber(0xa1, body))), nil
}

func BuildGetNameListResponse(cfg *MMSConfig, invoke byte) ([]byte, error) {
	var names []byte
	if cfg != nil {
		for _, obj := range cfg.Objects {
			names = append(names, ber(0x8a, []byte(obj.Name))...)
		}
	}
	return ber(0xa1, seq(ber(0x02, []byte{invoke}), ber(0xa1, ber(0xa0, names)))), nil
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
	return ber(0xa3, ber(0xa0, seq(variableSpecification(cfg), ber(0xa0, values)))), nil
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
	errorClass := ber(classTag, integerBytes(value))
	errorDetail := ber(0xa0, errorClass)
	serviceError := ber(0xa2, errorDetail)
	body := ber(0xa0, serviceError)
	return ber(0xa2, seq(ber(0x02, []byte{invoke}), body)), nil
}

func isDefaultAssociation(a *MMSAssociationConfig) bool {
	if a == nil {
		return true
	}
	return a.LocalDetail == 0 && a.MaxOutstandingCalling == 0 && a.MaxOutstandingCalled == 0 && a.NestingLevel == 0 && a.ServicesSupported == ""
}

func BuildAssociate(cfg *MMSConfig, response bool) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("mms: config is nil")
	}
	if isDefaultAssociation(cfg.Association) && cfg.IEDName == "" && len(cfg.Objects) == 0 {
		const request = "030000a502f0800d920506130100160102140200023305000102030434020001c1810081317fa003800101a278810412345678820487654321a425301002020101060452010001300406025101301102020103060528ca22020130040602510161433041020101a03c603aa1060628ca220203be30282e020103a029a82780040000fa0081010582010583010aa416800101810305f100820c05ee1c00000408000079ef18"
		const acknowledge = "030000a102f0800e900506130100160102140200023305000102030434020001c17f317da003800101a276830400000001a5"
		value := request
		if response {
			value = acknowledge
		}
		return hex.DecodeString(value)
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
	}
	if len(services) == 0 {
		services = []byte{5, 0xee, 0x1c, 0, 0, 4, 8, 0, 0, 0x79, 0xef, 0x18}
	}
	var detail []byte
	d := make([]byte, 4)
	binary.BigEndian.PutUint32(d, local)
	if response {
		detail = seq(ber(0x80, d), ber(0x81, []byte{calling}), ber(0x82, []byte{called}), ber(0x83, []byte{nesting}), ber(0xa4, seq(ber(0x80, []byte{1}), ber(0x81, []byte{5, 0xf1}), ber(0x82, []byte{5, 0}))))
	} else {
		detail = seq(ber(0x80, d), ber(0x81, []byte{calling}), ber(0x82, []byte{called}), ber(0x83, []byte{nesting}), ber(0xa4, seq(ber(0x80, []byte{1}), ber(0x81, []byte{5, 0xf1, 0}), ber(0x82, services))))
	}
	mms := ber(map[bool]byte{false: 0xa8, true: 0xa9}[response], detail)
	externalValue := seq([]byte{0x02, 0x01, 0x03}, ber(0xa0, mms))
	external := ber(0x28, externalValue)
	acseTag := byte(0x60)
	if response {
		acseTag = 0x61
	}
	acseBody := seq(ber(0xa1, []byte{6, 5, 0x28, 0xca, 0x22, 2, 3}), ber(0xbe, external))
	if response {
		acseBody = seq(ber(0xa1, []byte{6, 5, 0x28, 0xca, 0x22, 2, 3}), ber(0xa2, []byte{2, 1, 0}), ber(0xa3, []byte{0xa1, 3, 2, 1, 0}), ber(0xbe, external))
	}
	acse := ber(acseTag, acseBody)
	pcdlItem1 := seq(ber(0x02, []byte{0x01}), ber(0x06, []byte{0x52, 0x01, 0x00, 0x01}), ber(0x30, ber(0x06, []byte{0x51, 0x01})))
	pcdlItem3 := seq(ber(0x02, []byte{0x03}), ber(0x06, []byte{0x28, 0xca, 0x22, 0x02, 0x01}), ber(0x30, ber(0x06, []byte{0x51, 0x01})))
	pcdl := seq(ber(0x30, pcdlItem1), ber(0x30, pcdlItem3))
	cp := ber(0x31, seq(ber(0xa0, []byte{0x80, 0x01, 0x01}), pcdl, ber(0xa2, acse)))
	spduParams := []byte{0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, 0x14, 0x02, 0x00, 0x02, 0x33, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x34, 0x02, 0x00, 0x01}
	userData := seq([]byte{0xc1, 0x81, 0x00}, ber(0x81, cp))
	sessionPayload := seq(spduParams, userData)
	sessionTag := byte(0x0d)
	if response {
		sessionTag = 0x0e
	}
	session := append([]byte{sessionTag}, encodeLength(len(sessionPayload))...)
	session = append(session, sessionPayload...)
	return cotpDT(session)
}
