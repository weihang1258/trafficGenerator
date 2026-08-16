// Package mqtt implements the MQTT protocol planner.
package mqtt

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// encodeVBI encodes a value as a Variable Byte Integer (VBI).
// Returns up to 4 bytes. Max value: 268,435,455.
func encodeVBI(value int) ([]byte, error) {
	if value < 0 {
		return nil, fmt.Errorf("vbi: negative value %d", value)
	}
	if value > 268435455 {
		return nil, fmt.Errorf("vbi: value %d exceeds maximum 268435455", value)
	}

	var buf [4]byte
	var n int
	x := value
	for {
		encodedByte := x % 128
		x = x / 128
		if x > 0 {
			encodedByte |= 128
		}
		buf[n] = byte(encodedByte)
		n++
		if x == 0 {
			break
		}
	}
	return buf[:n], nil
}

// decodeVBI decodes a Variable Byte Integer from a byte slice.
// Returns the decoded value and the number of bytes consumed.
// Enforces the minimal-encoding rule (5.0 §1.5.5): a value must not be
// encoded with more bytes than necessary (e.g. 0x80 0x00 is invalid for 0).
func decodeVBI(data []byte) (value int, bytesConsumed int, err error) {
	multiplier := 1
	for i := 0; i < len(data); i++ {
		encodedByte := int(data[i])
		value += (encodedByte & 127) * multiplier
		if i >= 4 {
			return 0, 0, fmt.Errorf("vbi: malformed variable byte integer (exceeds 4 bytes)")
		}
		multiplier *= 128
		if (encodedByte & 128) == 0 {
			// Minimal-encoding check: the last byte must be non-zero unless
			// it is the only byte (value 0 encoded as a single 0x00).
			if i > 0 && encodedByte == 0 {
				return 0, 0, fmt.Errorf("vbi: non-minimal encoding")
			}
			return value, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("vbi: incomplete variable byte integer")
}

// encodeUTF8String encodes a string as a 2-byte big-endian length + UTF-8 bytes.
func encodeUTF8String(s string) []byte {
	b := []byte(s)
	if len(b) > 65535 {
		b = b[:65535]
	}
	result := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(result, uint16(len(b)))
	copy(result[2:], b)
	return result
}

// encodeBinaryData encodes binary data as a 2-byte big-endian length + raw bytes.
func encodeBinaryData(data []byte) []byte {
	if len(data) > 65535 {
		data = data[:65535]
	}
	result := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(result, uint16(len(data)))
	copy(result[2:], data)
	return result
}

// encodeStringPair encodes a key-value pair as 2-byte len(key) + key + 2-byte len(value) + value.
func encodeStringPair(key, value string) []byte {
	kb := []byte(key)
	vb := []byte(value)
	if len(kb) > 65535 {
		kb = kb[:65535]
	}
	if len(vb) > 65535 {
		vb = vb[:65535]
	}
	result := make([]byte, 2+len(kb)+2+len(vb))
	binary.BigEndian.PutUint16(result, uint16(len(kb)))
	copy(result[2:], kb)
	binary.BigEndian.PutUint16(result[2+len(kb):], uint16(len(vb)))
	copy(result[4+len(kb):], vb)
	return result
}

// encodeProperty encodes a single MQTT 5.0 property.
func encodeProperty(prop MQTTProperty) ([]byte, error) {
	id := prop.Identifier
	format := prop.Format
	if format == "" {
		format = "string"
	}

	var valueBytes []byte
	switch format {
	case "byte":
		v, err := strconv.Atoi(prop.Value)
		if err != nil || v < 0 || v > 255 {
			return nil, fmt.Errorf("invalid byte value: %s", prop.Value)
		}
		valueBytes = []byte{byte(v)}
	case "uint16":
		v, err := strconv.Atoi(prop.Value)
		if err != nil || v < 0 || v > 65535 {
			return nil, fmt.Errorf("invalid uint16 value: %s", prop.Value)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(v))
		valueBytes = b
	case "uint32":
		v, err := strconv.ParseUint(prop.Value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid uint32 value: %s", prop.Value)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v))
		valueBytes = b
	case "vbi":
		v, err := strconv.Atoi(prop.Value)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("invalid vbi value: %s", prop.Value)
		}
		valueBytes, err = encodeVBI(v)
		if err != nil {
			return nil, err
		}
	case "string":
		valueBytes = encodeUTF8String(prop.Value)
	case "binary":
		data, err := hexStringToBytes(prop.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid binary value: %w", err)
		}
		valueBytes = encodeBinaryData(data)
	case "stringpair":
		parts := strings.SplitN(prop.Value, "\x00", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid stringpair value: must contain NUL separator")
		}
		valueBytes = encodeStringPair(parts[0], parts[1])
	default:
		return nil, fmt.Errorf("unknown property format: %s", format)
	}

	idVBI, err := encodeVBI(id)
	if err != nil {
		return nil, fmt.Errorf("invalid property identifier: %w", err)
	}

	result := make([]byte, 0, len(idVBI)+len(valueBytes))
	result = append(result, idVBI...)
	result = append(result, valueBytes...)
	return result, nil
}

// hexStringToBytes converts a hex string to bytes.
func hexStringToBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex string must have even length")
	}
	return hexDecode(s)
}

// hexDecode decodes a hex string (no spaces, no 0x prefix).
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex string must have even length")
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexValue(s[i])
		lo, ok2 := hexValue(s[i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid hex character at position %d", i)
		}
		result[i/2] = byte(hi<<4 | lo)
	}
	return result, nil
}

// hexValue returns the numeric value of a hex digit.
func hexValue(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

// buildConnect builds a CONNECT packet.
// Version: 4 (3.1.1) or 5 (5.0).
func buildConnect(cfg *MQTTConfig) []byte {
	version := cfg.Version
	if version == 0 {
		version = 4
	}

	// Variable Header.
	var vh []byte
	// Protocol Name Length (2) + "MQTT" (4)
	vh = append(vh, 0x00, 0x04)
	vh = append(vh, []byte("MQTT")...)
	// Protocol Level.
	if version == 5 {
		vh = append(vh, 0x05)
	} else {
		vh = append(vh, 0x04)
	}

	// Connect Flags.
	var flags byte
	if cfg.Username != "" {
		flags |= 0x80
	}
	if cfg.Password != "" {
		flags |= 0x40
	}
	if cfg.Will != nil {
		flags |= 0x04 // Will Flag
		if cfg.Will.Retain {
			flags |= 0x20
		}
		flags |= byte((cfg.Will.QoS & 0x03) << 3)
	}
	cleanSession := true
	if cfg.CleanSession != nil {
		cleanSession = *cfg.CleanSession
	}
	// Empty ClientID forces CleanSession=true (3.1.1 §3.1.3.1: a zero-byte
	// ClientID is only allowed with CleanSession=1).
	if cfg.ClientID == "" {
		cleanSession = true
	}
	if cleanSession {
		flags |= 0x02
	}
	// bit0 reserved = 0.
	vh = append(vh, flags)

	// Keep Alive.
	keepAlive := 60
	if cfg.KeepAlive != nil {
		keepAlive = *cfg.KeepAlive
	}
	vh = append(vh, byte(keepAlive>>8), byte(keepAlive&0xFF))

	// 5.0: Properties.
	if version == 5 {
		props := buildProperties(cfg.Properties)
		propsVBI, _ := encodeVBI(len(props))
		vh = append(vh, propsVBI...)
		vh = append(vh, props...)
	}

	// Payload.
	var payload []byte
	// ClientID. Empty values are resolved by emitSessionFlow before encoding.
	clientID := cfg.ClientID
	payload = append(payload, encodeUTF8String(clientID)...)

	// Will Properties (5.0 only).
	if version == 5 && cfg.Will != nil {
		var willProps []byte
		if cfg.Will.DelayInterval > 0 {
			idVBI, _ := encodeVBI(0x18)
			willProps = append(willProps, idVBI...)
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(cfg.Will.DelayInterval))
			willProps = append(willProps, b...)
		}
		willVBI, _ := encodeVBI(len(willProps))
		payload = append(payload, willVBI...)
		payload = append(payload, willProps...)
	}

	// Will Topic and Payload.
	if cfg.Will != nil {
		payload = append(payload, encodeUTF8String(cfg.Will.Topic)...)
		payload = append(payload, encodeBinaryData([]byte(cfg.Will.Payload))...)
	}

	// Username/Password.
	if cfg.Username != "" {
		payload = append(payload, encodeUTF8String(cfg.Username)...)
	}
	if cfg.Password != "" {
		payload = append(payload, encodeUTF8String(cfg.Password)...)
	}

	// Fixed Header.
	remainingLen := len(vh) + len(payload)
	vbi, _ := encodeVBI(remainingLen)
	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, 0x10) // CONNECT type + flags=0
	result = append(result, vbi...)
	result = append(result, vh...)
	result = append(result, payload...)

	return result
}

// buildConnack builds a CONNACK packet.
func buildConnack(cfg *MQTTConfig) []byte {
	version := cfg.Version
	if version == 0 {
		version = 4
	}

	var payload []byte
	// Session Present.
	var sp byte
	if cfg.ConnectAckSessionPresent {
		sp = 0x01
	}
	payload = append(payload, sp)

	// Reason Code / Return Code.
	payload = append(payload, byte(cfg.ConnectAckCode))

	// 5.0: Properties Length.
	if version == 5 {
		var props []byte
		for _, prop := range cfg.ConnackProperties {
			enc, err := encodeProperty(prop)
			if err == nil {
				props = append(props, enc...)
			}
		}
		vbi, _ := encodeVBI(len(props))
		payload = append(payload, vbi...)
		payload = append(payload, props...)
	}

	remainingLen := len(payload)
	vbi, _ := encodeVBI(remainingLen)

	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, 0x20) // CONNACK type + flags=0
	result = append(result, vbi...)
	result = append(result, payload...)
	return result
}

// buildPublish builds a PUBLISH packet.
func buildPublish(msg MQTTMessage, version int) []byte {
	// Fixed header first byte: type=3, flags=DUP|QoS|Retain.
	var firstByte byte = 0x30
	if msg.DUP {
		firstByte |= 0x08
	}
	firstByte |= byte((msg.QoS & 0x03) << 1)
	if msg.Retain {
		firstByte |= 0x01
	}

	// Variable Header.
	var vh []byte
	// Topic Name.
	vh = append(vh, encodeUTF8String(msg.Topic)...)

	// Packet ID (if QoS > 0).
	if msg.QoS > 0 {
		vh = append(vh, byte(msg.PacketID>>8), byte(msg.PacketID&0xFF))
	}

	// 5.0: Properties.
	if version == 5 {
		props := buildProperties(msg.Properties)
		propsVBI, _ := encodeVBI(len(props))
		vh = append(vh, propsVBI...)
		vh = append(vh, props...)
	}

	// Payload.
	payload := []byte(msg.Payload)

	remainingLen := len(vh) + len(payload)
	vbi, _ := encodeVBI(remainingLen)

	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, firstByte)
	result = append(result, vbi...)
	result = append(result, vh...)
	result = append(result, payload...)
	return result
}

// buildPuback builds a PUBACK packet.
func buildPuback(packetID uint16, version int) []byte {
	var payload []byte
	payload = append(payload, byte(packetID>>8), byte(packetID&0xFF))
	if version == 5 {
		payload = append(payload, 0x00) // Reason Code = Success.
		payload = append(payload, 0x00) // Properties Length = 0.
	}
	remainingLen := len(payload)
	vbi, _ := encodeVBI(remainingLen)
	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, 0x40) // PUBACK type + flags=0
	result = append(result, vbi...)
	result = append(result, payload...)
	return result
}

// buildPubrec builds a PUBREC packet.
func buildPubrec(packetID uint16, version int) []byte {
	var payload []byte
	payload = append(payload, byte(packetID>>8), byte(packetID&0xFF))
	if version == 5 {
		payload = append(payload, 0x00) // Reason Code = Success.
		payload = append(payload, 0x00) // Properties Length = 0.
	}
	remainingLen := len(payload)
	vbi, _ := encodeVBI(remainingLen)
	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, 0x50) // PUBREC type + flags=0
	result = append(result, vbi...)
	result = append(result, payload...)
	return result
}

// buildPubrel builds a PUBREL packet.
func buildPubrel(packetID uint16, version int) []byte {
	var payload []byte
	payload = append(payload, byte(packetID>>8), byte(packetID&0xFF))
	if version == 5 {
		payload = append(payload, 0x00) // Reason Code = Success.
		payload = append(payload, 0x00) // Properties Length = 0.
	}
	remainingLen := len(payload)
	vbi, _ := encodeVBI(remainingLen)
	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, 0x62) // PUBREL type=6 + flags=0x02
	result = append(result, vbi...)
	result = append(result, payload...)
	return result
}

// buildPubcomp builds a PUBCOMP packet.
func buildPubcomp(packetID uint16, version int) []byte {
	var payload []byte
	payload = append(payload, byte(packetID>>8), byte(packetID&0xFF))
	if version == 5 {
		payload = append(payload, 0x00) // Reason Code = Success.
		payload = append(payload, 0x00) // Properties Length = 0.
	}
	remainingLen := len(payload)
	vbi, _ := encodeVBI(remainingLen)
	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, 0x70) // PUBCOMP type + flags=0
	result = append(result, vbi...)
	result = append(result, payload...)
	return result
}

// buildSubscribe builds a SUBSCRIBE packet.
func buildSubscribe(sub MQTTSubscribe, version int) []byte {
	var payload []byte
	// Packet ID.
	payload = append(payload, byte(sub.PacketID>>8), byte(sub.PacketID&0xFF))

	// 5.0: Properties. SUBSCRIBE supports Subscription Identifier
	// (0x0B) and User Property (0x26) — see validateProperties 0x82
	// whitelist. MQTT 5.0 §3.8.2.1.2.
	if version == 5 {
		if len(sub.Properties) > 0 {
			props := buildProperties(sub.Properties)
			vbi, _ := encodeVBI(len(props))
			payload = append(payload, vbi...)
			payload = append(payload, props...)
		} else {
			payload = append(payload, 0x00) // Properties Length = 0.
		}
	}

	// Filters.
	for _, f := range sub.Filters {
		payload = append(payload, encodeUTF8String(f.Filter)...)
		var opts byte
		if version == 5 {
			// 5.0 subscription options.
			if f.NoLocal {
				opts |= 0x04
			}
			if f.RetainAsPublished {
				opts |= 0x08
			}
			opts |= byte((f.RetainHandling & 0x03) << 4)
		}
		// QoS.
		if version == 4 {
			// 3.1.1: only QoS in lower 2 bits, upper bits must be 0.
			payload = append(payload, byte(f.QoS&0x03))
		} else {
			payload = append(payload, opts|byte(f.QoS&0x03))
		}
	}

	remainingLen := len(payload)
	vbi, _ := encodeVBI(remainingLen)
	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, 0x82) // SUBSCRIBE type=8 + flags=0x02
	result = append(result, vbi...)
	result = append(result, payload...)
	return result
}

// buildSuback builds a SUBACK packet.
func buildSuback(packetID uint16, reasonCodes []int, filterCount, version int) []byte {
	var payload []byte
	// Packet ID.
	payload = append(payload, byte(packetID>>8), byte(packetID&0xFF))

	// 5.0: Properties.
	if version == 5 {
		payload = append(payload, 0x00) // Properties Length = 0.
	}

	// Reason Codes. Empty means one QoS-0 grant per filter.
	if len(reasonCodes) == 0 {
		reasonCodes = make([]int, filterCount)
	}
	for _, rc := range reasonCodes {
		payload = append(payload, byte(rc))
	}

	remainingLen := len(payload)
	vbi, _ := encodeVBI(remainingLen)
	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, 0x90) // SUBACK type + flags=0
	result = append(result, vbi...)
	result = append(result, payload...)
	return result
}

// buildPingreq builds a PINGREQ packet.
func buildPingreq() []byte {
	return []byte{0xC0, 0x00}
}

// buildPingresp builds a PINGRESP packet.
func buildPingresp() []byte {
	return []byte{0xD0, 0x00}
}

// buildDisconnect builds a DISCONNECT packet.
func buildDisconnect(version int, reasonCode int) []byte {
	if version == 4 || version == 0 {
		return []byte{0xE0, 0x00}
	}
	// 5.0: Variable header = Reason Code + Properties Length.
	payload := []byte{byte(reasonCode), 0x00}
	remainingLen := len(payload)
	vbi, _ := encodeVBI(remainingLen)
	result := make([]byte, 0, 1+len(vbi)+remainingLen)
	result = append(result, 0xE0) // DISCONNECT type + flags=0
	result = append(result, vbi...)
	result = append(result, payload...)
	return result
}

// buildProperties encodes a list of MQTT 5.0 properties.
func buildProperties(props []MQTTProperty) []byte {
	var result []byte
	for _, prop := range props {
		b, err := encodeProperty(prop)
		if err != nil {
			continue
		}
		result = append(result, b...)
	}
	return result
}
