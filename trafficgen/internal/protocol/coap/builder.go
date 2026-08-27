package coap

import (
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	optObserve       = 6
	optURIPath       = 11
	optContentFormat = 12
	optURIQuery      = 15
	optAccept        = 17
)

type option struct {
	number uint16
	value  []byte
}

func BuildMessage(cfg *CoAPConfig, response bool) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("coap: config is nil")
	}
	version := uint8(1)
	if cfg.Version != 0 {
		version = cfg.Version
	}
	if version != 1 {
		return nil, fmt.Errorf("coap: version %d is invalid", version)
	}
	token := cfg.Token
	if len(token) > 8 {
		return nil, fmt.Errorf("coap: token length %d exceeds 8", len(token))
	}
	if cfg.TokenLength != 0 && int(cfg.TokenLength) != len(token) {
		return nil, fmt.Errorf("coap: token length does not match token")
	}
	code := methodCode(cfg.Method)
	msgType := uint8(0)
	if response {
		msgType = 2
		var err error
		code, err = responseCode(cfg.ResponseCode)
		if err != nil {
			return nil, err
		}
	} else if cfg.Response != nil && !*cfg.Response {
		msgType = 1
	}
	if cfg.Code != 0 && !response {
		code = cfg.Code
	}
	if code == 0 {
		return nil, fmt.Errorf("coap: code is invalid")
	}
	out := make([]byte, 4, 4+len(token))
	out[0] = (version << 6) | (msgType << 4) | uint8(len(token))
	out[1] = code
	binary.BigEndian.PutUint16(out[2:4], cfg.MessageID)
	out = append(out, token...)
	var opts []option
	if !response {
		for _, p := range cfg.Path {
			opts = append(opts, option{optURIPath, []byte(p)})
		}
		for _, q := range cfg.Query {
			opts = append(opts, option{optURIQuery, []byte(q)})
		}
		if cfg.Observe != nil {
			opts = append(opts, option{optObserve, uintBytes32(cfg.Observe.Sequence)})
		}
		if cfg.ContentFormat != 0 {
			opts = append(opts, option{optContentFormat, uintBytes(cfg.ContentFormat)})
		}
		if cfg.Accept != nil {
			opts = append(opts, option{optAccept, uintBytes(*cfg.Accept)})
		}
	} else if cfg.ResponseContentFormat != 0 {
		opts = append(opts, option{optContentFormat, uintBytes(cfg.ResponseContentFormat)})
	}
	sort.SliceStable(opts, func(i, j int) bool { return opts[i].number < opts[j].number })
	prev := uint16(0)
	for _, o := range opts {
		if o.number < prev {
			return nil, fmt.Errorf("coap: options out of order")
		}
		out = append(out, encodeOption(o.number-prev, uint16(len(o.value)))...)
		out = append(out, o.value...)
		prev = o.number
	}
	payload := cfg.Payload
	if response {
		payload = cfg.ResponsePayload
	}
	if len(payload) > 0 {
		out = append(out, 0xff)
		out = append(out, payload...)
	}
	return out, nil
}

func methodCode(method string) uint8 {
	switch method {
	case "GET", "get":
		return 1
	case "POST", "post":
		return 2
	case "PUT", "put":
		return 3
	case "DELETE", "delete":
		return 4
	}
	return 0
}
func responseCode(s string) (uint8, error) {
	switch s {
	case "2.01":
		return 65, nil
	case "2.02":
		return 66, nil
	case "2.04":
		return 68, nil
	case "2.05":
		return 69, nil
	case "4.00":
		return 128, nil
	case "4.04":
		return 132, nil
	case "4.13":
		return 141, nil
	case "5.00":
		return 160, nil
	}
	return 0, fmt.Errorf("coap: response code %q is invalid", s)
}
func uintBytes(v uint16) []byte {
	if v <= 255 {
		return []byte{byte(v)}
	}
	return []byte{byte(v >> 8), byte(v)}
}
func uintBytes32(v uint32) []byte {
	if v == 0 {
		return nil
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	i := 0
	for i < 3 && b[i] == 0 {
		i++
	}
	return b[i:]
}
func encodeOption(delta, length uint16) []byte {
	d, de := optionNibble(delta)
	l, le := optionNibble(length)
	out := []byte{d<<4 | l}
	out = append(out, de...)
	out = append(out, le...)
	return out
}
func optionNibble(v uint16) (byte, []byte) {
	if v <= 12 {
		return byte(v), nil
	}
	if v <= 268 {
		return 13, []byte{byte(v - 13)}
	}
	return 14, []byte{byte((v - 269) >> 8), byte(v - 269)}
}
