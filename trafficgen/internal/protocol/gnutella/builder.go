// Package gnutella implements the Gnutella wire profile terminal layer (B5)：
// TCP 6346 上的 Gnutella 0.6 HTTP-like 握手（ASCII + CRLF）与 23 字节二进制
// 消息。builder.go 只做线格式编码（纯函数），状态机校验/事件折叠在
// layer_gen.go。帧布局见 docs/protocol-designs/53-gnutella-design.md §3–§4：
//
//	消息头: MessageID(16) | Descriptor(1) | TTL(1) | Hops(1) | PayloadLength(4, LE)
//	Descriptor: PING 0x00 / PONG 0x01 / PUSH 0x40 / QUERY 0x80 / QUERY_HIT 0x81 /
//	            VENDOR 0x31
//
// PayloadLength 为小端 uint32（设计 §3.2 唯一显式钉死的端序），只计 payload；
// payload 内多字节整数（端口/速度/文件序号/大小）同样小端——Gnutella 0.6 规范
//（GDF）全字段 Intel 序，tshark dissector 亦按小端解码（2026-08 探针实证）。
// 地址字段为 4B 裸网络序字节（不随 profile 变端序）；GUID/ServentID 为 16B 裸
// 字节。地址字段长度由 profile 决定（gnutella_v060→4B、gnutella_ipv6_v1→16B），
// 不随外层地址族变化。tshark 无本协议完整 dissector 支撑（QueryHit 存在已知
// 解析缺陷，见 pcaptest.IsMalformedWhitelisted），断言走 TCP 字段与帧字节。
package gnutella

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// descriptor 值（设计 §3.2）。
const (
	descPing     = 0x00
	descPong     = 0x01
	descPush     = 0x40
	descQuery    = 0x80
	descQueryHit = 0x81
	descVendor   = 0x31
)

// 常量。
const (
	headerLen       = 23
	defaultFrameMax = 4096
	defaultDstPort  = 6346
	defaultTTL      = 7
	defaultMinSpeed = 0

	defaultVendorID = "GTKG"
	// defaultGUID 是 16B 非全零缺省 GUID（设计 §7：MessageID 全零为边界值
	// 由 fixture 显式声明，缺省非零）。
	defaultGUIDHex = "101112131415161718191a1b1c1d1e1f"
	// defaultNodeHex 是握手 X-Node 缺省值。
	defaultNodeHex = "0a0b0c0d0e0f0a0b"

	profileV060 = "gnutella_v060"
	profileV6   = "gnutella_ipv6_v1"
)

// addressLen resolves the profile-declared address field width。
func addressLen(profile string) int {
	if profile == profileV6 {
		return 16
	}
	return 4
}

// resolveGUID validates a 16-byte GUID（空用缺省；错误长度拒绝）。
func resolveGUID(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return hexBytes(defaultGUIDHex)
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("gnutella: message_id must be 16 bytes, got %d (message)", len(b))
	}
	return b, nil
}

func hexBytes(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := range out {
		hi := hexVal(s[i*2])
		lo := hexVal(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("gnutella: %q is not valid hex", s)
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// resolveAddress validates the profile-declared address bytes。
func resolveAddress(addr []byte, profile string) ([]byte, error) {
	if len(addr) == 0 {
		// 缺省地址：profile 对应宽度的文档值（v4 10.0.0.9；v6 2001:db8::9）。
		if addressLen(profile) == 16 {
			b := make([]byte, 16)
			b[0], b[1] = 0x20, 0x01
			b[2], b[3] = 0x0d, 0xb8
			b[15] = 9
			return b, nil
		}
		return []byte{10, 0, 0, 9}, nil
	}
	if len(addr) != addressLen(profile) {
		return nil, fmt.Errorf("gnutella: address must be %d bytes for profile, got %d (address/payload)", addressLen(profile), len(addr))
	}
	return addr, nil
}

// ---- handshake ----

// headerLines serialises the capability map in sorted key order (字节确定性)。
func headerLines(headers map[string]string) []byte {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, k := range keys {
		out.WriteString(k)
		out.WriteString(": ")
		out.WriteString(headers[k])
		out.WriteString("\r\n")
	}
	return []byte(out.String())
}

// defaultClientHeaders/defaultServerHeaders fill the omitted capability
// lines (键序稳定)。
func defaultClientHeaders() map[string]string {
	return map[string]string{
		"User-Agent":       "trafficgen/1.0",
		"X-Query-Routing":  "0.1",
		"X-Ultrapeer":      "False",
		"X-Node":           defaultNodeHex,
	}
}

func defaultServerHeaders() map[string]string {
	return map[string]string{
		"X-Query-Routing": "0.1",
		"X-Ultrapeer":     "False",
		"X-Node":          defaultNodeHex,
	}
}

// BuildHandshake encodes the ASCII handshake frames。
func BuildHandshake(kind string, headers map[string]string) []byte {
	var out strings.Builder
	switch kind {
	case "connect":
		out.WriteString("GNUTELLA CONNECT/0.6\r\n")
		if headers == nil {
			headers = defaultClientHeaders()
		}
		out.Write(headerLines(headers))
	case "ok":
		out.WriteString("GNUTELLA/0.6 200 OK\r\n")
		if headers == nil {
			headers = defaultServerHeaders()
		}
		out.Write(headerLines(headers))
	case "refuse":
		out.WriteString("GNUTELLA/0.6 503 Busy\r\n")
		if headers == nil {
			headers = defaultServerHeaders()
		}
		out.Write(headerLines(headers))
	}
	out.WriteString("\r\n")
	return []byte(out.String())
}

// ---- binary messages ----

// messageHeader is the 23-byte header (PayloadLength 小端)。
func messageHeader(guid []byte, desc byte, ttl, hops uint8, payloadLen int) []byte {
	out := make([]byte, 0, headerLen)
	out = append(out, guid...)
	out = append(out, desc, ttl, hops)
	out = binary.LittleEndian.AppendUint32(out, uint32(payloadLen))
	return out
}

// eventDefaults resolves the kind-derived (descriptor, direction, isHandshake)。
func eventDefaults(e *core.GnutellaEvent) (byte, string, bool, bool) {
	switch e.Kind {
	case "connect":
		return 0, "c2s", true, true
	case "ok", "refuse":
		return 0, "s2c", true, true
	case "ping":
		return descPing, "c2s", false, true
	case "pong":
		return descPong, "s2c", false, true
	case "push":
		return descPush, "c2s", false, true
	case "query":
		return descQuery, "c2s", false, true
	case "query_hit":
		return descQueryHit, "s2c", false, true
	case "vendor":
		return descVendor, "c2s", false, true
	}
	return 0, "", false, false
}

// buildPayload encodes the descriptor-specific payload (设计 §4)。
func buildPayload(e *core.GnutellaEvent, profile string) ([]byte, error) {
	switch e.Kind {
	case "ping":
		return e.Payload, nil // 可选扩展：通常空（PayloadLength=0 最小消息）
	case "pong":
		addr, err := resolveAddress(e.PongAddress, profile)
		if err != nil {
			return nil, err
		}
		out := binary.LittleEndian.AppendUint16(nil, e.PongPort)
		out = append(out, addr...)
		out = binary.LittleEndian.AppendUint32(out, e.Files)
		out = binary.LittleEndian.AppendUint32(out, e.KB)
		return out, nil
	case "query":
		criteria := e.Criteria
		out := binary.LittleEndian.AppendUint16(nil, e.MinSpeed)
		out = append(out, []byte(criteria)...)
		return append(out, 0), nil // NUL 终止
	case "query_hit":
		if e.Hits != len(e.Results) {
			return nil, fmt.Errorf("gnutella: query_hit hits %d does not equal %d result entries (payload/hits)", e.Hits, len(e.Results))
		}
		addr, err := resolveAddress(e.HitAddress, profile)
		if err != nil {
			return nil, err
		}
		out := []byte{byte(e.Hits)}
		out = binary.LittleEndian.AppendUint16(out, e.HitPort)
		out = append(out, addr...)
		out = binary.LittleEndian.AppendUint32(out, e.Speed)
		for _, r := range e.Results {
			out = binary.LittleEndian.AppendUint32(out, r.FileIndex)
			out = binary.LittleEndian.AppendUint32(out, r.FileSize)
			out = append(out, []byte(r.Name)...)
			out = append(out, 0) // NUL 终止文件名
		}
		servent, err := resolveGUID(e.ServentID)
		if err != nil {
			return nil, fmt.Errorf("gnutella: servent_id must be 16 bytes (servent)")
		}
		out = append(out, servent...)
		return out, nil
	case "push":
		servent, err := resolveGUID(e.ServentID)
		if err != nil {
			return nil, fmt.Errorf("gnutella: servent_id must be 16 bytes (servent)")
		}
		addr, err := resolveAddress(e.PushAddress, profile)
		if err != nil {
			return nil, err
		}
		out := append([]byte{}, servent...)
		out = binary.LittleEndian.AppendUint32(out, e.FileIndex)
		out = append(out, addr...)
		out = binary.LittleEndian.AppendUint16(out, e.PushPort)
		return out, nil
	case "vendor":
		vid := e.VendorID
		if vid == "" {
			vid = defaultVendorID
		}
		if len(vid) != 4 {
			return nil, fmt.Errorf("gnutella: vendor_id must be 4 ASCII chars, got %q (payload)", vid)
		}
		out := []byte(vid)
		out = binary.LittleEndian.AppendUint16(out, e.Selector)
		out = binary.LittleEndian.AppendUint16(out, e.Version)
		return append(out, e.Payload...), nil
	}
	return nil, fmt.Errorf("gnutella: unknown descriptor kind %q (descriptor)", e.Kind)
}

// BuildMessage encodes one binary message (23B header + payload)。
func BuildMessage(e *core.GnutellaEvent, profile string) ([]byte, error) {
	desc, _, _, ok := eventDefaults(e)
	if !ok {
		return nil, fmt.Errorf("gnutella: unknown frame type %q (descriptor)", e.Kind)
	}
	payload, err := buildPayload(e, profile)
	if err != nil {
		return nil, err
	}
	guid, err := resolveGUID(e.MessageID)
	if err != nil {
		return nil, err
	}
	out := messageHeader(guid, desc, e.TTL, e.Hops, len(payload))
	return append(out, payload...), nil
}

// CheckFrameMax guards the message size against frame_max。
func CheckFrameMax(frame []byte, frameMax uint32) error {
	limit := frameMax
	if limit == 0 {
		limit = defaultFrameMax
	}
	if uint64(len(frame)) > uint64(limit) {
		return fmt.Errorf("gnutella: message length %d exceeds frame_max %d (length)", len(frame), limit)
	}
	return nil
}
