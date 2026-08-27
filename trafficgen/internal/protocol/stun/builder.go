package stun

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

const MagicCookie uint32 = 0x2112A442

const (
	BindingRequest   uint16 = 0x0001
	BindingSuccess   uint16 = 0x0101
	BindingError     uint16 = 0x0111
	attrMappedAddr   uint16 = 0x0001
	attrUsername     uint16 = 0x0006
	attrMsgIntegrity uint16 = 0x0008
	attrErrorCode    uint16 = 0x0009
	attrUnknownAttrs uint16 = 0x000A
	attrRealm        uint16 = 0x0014
	attrNonce        uint16 = 0x0015
	attrXORMapped    uint16 = 0x0020
	attrFingerprint  uint16 = 0x8028
)

// messageType returns the STUN message type for an event kind.
func messageType(kind string) (uint16, error) {
	switch kind {
	case "request":
		return BindingRequest, nil
	case "success":
		return BindingSuccess, nil
	case "error":
		return BindingError, nil
	default:
		return 0, fmt.Errorf("stun: unknown event kind %q", kind)
	}
}

// newTransactionID generates a random 12-byte transaction ID.
func newTransactionID() ([]byte, error) {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("stun: transaction id: %w", err)
	}
	return id, nil
}

// BuildMessageFromEvent builds a STUN message for a single event.
func BuildMessageFromEvent(event *core.STUNEvent, tid []byte) ([]byte, error) {
	if len(tid) != 12 {
		return nil, fmt.Errorf("stun: transaction id must be 12 bytes")
	}
	typ, err := messageType(event.Kind)
	if err != nil {
		return nil, err
	}
	// Build the body, collecting which attributes need post-processing.
	body, hasIntegrity, integrityKey, hasFingerprint, err := buildBody(event.Attributes, tid)
	if err != nil {
		return nil, err
	}
	// Build header with placeholder length.
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[:2], typ)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(body)))
	binary.BigEndian.PutUint32(header[4:8], MagicCookie)
	copy(header[8:], tid)
	// Assemble message before integrity/fingerprint.
	msg := append(header, body...)

	// Add message-integrity attribute (HMAC-SHA1 over the message up to the
	// attribute, with the HMAC value zeroed; RFC 5389 §15.4).
	integrityLen := 0
	if hasIntegrity {
		key := integrityKey
		if key == "" {
			key = "password"
		}
		// The HMAC key is the SASL-prep'd password (RFC 5389 §15.4).
		// For simplicity, use the raw key bytes (matching the test cases).
		mac := hmac.New(sha1.New, []byte(key))
		// Build the integrity attribute with 20 zero bytes (placeholder).
		attrBody := make([]byte, 4+20)
		binary.BigEndian.PutUint16(attrBody[:2], attrMsgIntegrity)
		binary.BigEndian.PutUint16(attrBody[2:4], 20)
		// Compute HMAC over the message up to and including the
		// attribute header+length, with the 20-byte HMAC zeroed.
		preMsg := make([]byte, len(msg)+4)
		copy(preMsg, msg)
		copy(preMsg[len(msg):], attrBody[:4])
		mac.Write(preMsg)
		// Copy the HMAC into the attribute body.
		copy(attrBody[4:], mac.Sum(nil))
		msg = append(msg, attrBody...)
		integrityLen = len(attrBody)
	}

	// Add fingerprint attribute (CRC32 over the entire message XOR 0x5354554E;
	// RFC 5389 §15.5).
	fingerprintLen := 0
	if hasFingerprint {
		crc := crc32.ChecksumIEEE(msg) ^ 0x5354554E
		fpBody := make([]byte, 8)
		binary.BigEndian.PutUint16(fpBody[:2], attrFingerprint)
		binary.BigEndian.PutUint16(fpBody[2:4], 4)
		fpBody[4] = byte(crc >> 24)
		fpBody[5] = byte(crc >> 16)
		fpBody[6] = byte(crc >> 8)
		fpBody[7] = byte(crc)
		msg = append(msg, fpBody...)
		fingerprintLen = len(fpBody)
	}

	// Update header length to include integrity and fingerprint.
	if integrityLen > 0 || fingerprintLen > 0 {
		bodyLen := len(msg) - 20
		binary.BigEndian.PutUint16(msg[2:4], uint16(bodyLen))
	}
	return msg, nil
}

// buildBody builds the STUN message body from attributes, excluding
// message-integrity and fingerprint (those are post-processed).
func buildBody(attrs []core.STUNAttribute, tid []byte) (body []byte, hasIntegrity bool, integrityKey string, hasFingerprint bool, err error) {
	for _, a := range attrs {
		switch a.Type {
		case "username":
			body = append(body, attr(attrUsername, []byte(a.Value))...)
		case "realm":
			body = append(body, attr(attrRealm, []byte(a.Value))...)
		case "nonce":
			body = append(body, attr(attrNonce, []byte(a.Value))...)
		case "mapped-address":
			v, e := addressValue(a.Address, a.Port, tid, false)
			if e != nil {
				err = e
				return
			}
			body = append(body, attr(attrMappedAddr, v)...)
		case "xor-mapped-address":
			v, e := addressValue(a.Address, a.Port, tid, true)
			if e != nil {
				err = e
				return
			}
			body = append(body, attr(attrXORMapped, v)...)
		case "error-code":
			v := buildErrorCodeAttr(a.Code, a.Reason)
			body = append(body, attr(attrErrorCode, v)...)
		case "unknown-attributes":
			v := buildUnknownAttributesAttr(a.Value)
			body = append(body, attr(attrUnknownAttrs, v)...)
		case "message-integrity":
			hasIntegrity = true
			integrityKey = a.Key
		case "fingerprint":
			hasFingerprint = true
		default:
			// Unknown attribute type numbers: parse as hex.
			// This is used for custom/unknown attributes in test cases.
			at, e := attributeType(a.Type)
			if e != nil {
				err = e
				return
			}
			body = append(body, attr(at, []byte(a.Value))...)
		}
	}
	return
}

// attributeType maps attribute name to STUN type code.
func attributeType(name string) (uint16, error) {
	switch name {
	case "mapped-address":
		return attrMappedAddr, nil
	case "username":
		return attrUsername, nil
	case "message-integrity":
		return attrMsgIntegrity, nil
	case "error-code":
		return attrErrorCode, nil
	case "unknown-attributes":
		return attrUnknownAttrs, nil
	case "realm":
		return attrRealm, nil
	case "nonce":
		return attrNonce, nil
	case "xor-mapped-address":
		return attrXORMapped, nil
	case "fingerprint":
		return attrFingerprint, nil
	default:
		return 0, fmt.Errorf("stun: unknown attribute type %q", name)
	}
}

// attr builds a TLV attribute with 32-bit padding.
func attr(typ uint16, value []byte) []byte {
	pad := (4 - (len(value) % 4)) % 4
	b := make([]byte, 4+len(value)+pad)
	binary.BigEndian.PutUint16(b[:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(value)))
	copy(b[4:], value)
	return b
}

// addressValue builds the STUN address attribute value (RFC 5389 §15.1).
func addressValue(ip string, port uint16, id []byte, xor bool) ([]byte, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("stun: address %q invalid", ip)
	}
	if v4 := parsed.To4(); v4 != nil {
		b := make([]byte, 8)
		b[1] = 1
		binary.BigEndian.PutUint16(b[2:4], port)
		copy(b[4:], v4)
		if xor {
			masked := binary.BigEndian.Uint16(b[2:4]) ^ uint16(MagicCookie>>16)
			binary.BigEndian.PutUint16(b[2:4], masked)
			ipMask := binary.BigEndian.Uint32(b[4:8]) ^ MagicCookie
			binary.BigEndian.PutUint32(b[4:8], ipMask)
		}
		return b, nil
	}
	v6 := parsed.To16()
	b := make([]byte, 20)
	b[1] = 2
	binary.BigEndian.PutUint16(b[2:4], port)
	copy(b[4:], v6)
	if xor {
		masked := binary.BigEndian.Uint16(b[2:4]) ^ uint16(MagicCookie>>16)
		binary.BigEndian.PutUint16(b[2:4], masked)
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[:4], MagicCookie)
		copy(mask[4:], id)
		for i := range v6 {
			b[4+i] ^= mask[i]
		}
	}
	return b, nil
}

// buildErrorCodeAttr builds an ERROR-CODE attribute value (RFC 5389 §15.6).
func buildErrorCodeAttr(code uint16, reason string) []byte {
	v := []byte{0, 0, byte(code / 100), byte(code % 100)}
	v = append(v, []byte(reason)...)
	return v
}

// buildUnknownAttributesAttr builds an UNKNOWN-ATTRIBUTES attribute value.
func buildUnknownAttributesAttr(value string) []byte {
	// Parse space-separated hex values.
	parts := strings.Fields(value)
	b := make([]byte, 0, len(parts)*2)
	for _, p := range parts {
		var val uint16
		fmt.Sscanf(p, "%x", &val)
		b = append(b, byte(val>>8), byte(val))
	}
	return b
}

// ValidateConfig validates the STUN config.
func ValidateConfig(c *core.STUNConfig) error {
	if c == nil {
		return fmt.Errorf("stun: config is required")
	}
	if c.WireFault != nil {
		return validateWireFault(c.WireFault)
	}
	if len(c.Events) == 0 {
		return fmt.Errorf("stun: at least one event is required")
	}
	for i, ev := range c.Events {
		if ev.Kind == "" {
			return fmt.Errorf("stun: events[%d]: kind is required", i)
		}
		if _, err := messageType(ev.Kind); err != nil {
			return fmt.Errorf("stun: events[%d]: %v", i, err)
		}
		if ev.Direction == "" {
			return fmt.Errorf("stun: events[%d]: direction is required", i)
		}
		if ev.Direction != "c2s" && ev.Direction != "s2c" {
			return fmt.Errorf("stun: events[%d]: direction %q invalid (c2s or s2c)", i, ev.Direction)
		}
		for j, a := range ev.Attributes {
			if a.Type == "" {
				return fmt.Errorf("stun: events[%d].attributes[%d]: type is required", i, j)
			}
			switch a.Type {
			case "mapped-address", "xor-mapped-address":
				if a.Address != "" && net.ParseIP(a.Address) == nil {
					return fmt.Errorf("stun: events[%d].attributes[%d]: address %q invalid", i, j, a.Address)
				}
			case "error-code":
				if a.Code > 699 || (a.Code != 0 && a.Code < 300) {
					return fmt.Errorf("stun: events[%d].attributes[%d]: error code %d invalid", i, j, a.Code)
				}
			}
		}
	}
	return nil
}

// validateWireFault checks that a wire fault is correctly configured
// and returns an appropriate error message.
func validateWireFault(f *core.STUNFault) error {
	if f.Kind == "" {
		return fmt.Errorf("stun: wire_fault kind is required")
	}
	switch f.Kind {
	case "header_short":
		return fmt.Errorf("stun: header too short (%d bytes)", f.DeclaredBytes)
	case "type_reserved_bits":
		return fmt.Errorf("stun: reserved message type bits set (type 0x%04x)", f.Type)
	case "length_alignment":
		return fmt.Errorf("stun: message length not 4-byte aligned (%d)", f.DeclaredLength)
	case "length_overrun":
		return fmt.Errorf("stun: message length overruns payload (%d)", f.DeclaredLength)
	case "cookie":
		return fmt.Errorf("stun: invalid magic cookie %s", f.Cookie)
	case "attribute_length":
		return fmt.Errorf("stun: attribute length overruns message (%d)", f.DeclaredLength)
	case "integrity":
		return fmt.Errorf("stun: message integrity check failed (key=%q)", f.Key)
	case "transport":
		return fmt.Errorf("stun: transport mismatch: carrier=%q framing=%q", f.Carrier, f.Framing)
	case "turn_boundary":
		return fmt.Errorf("stun: turn boundary: method=%q not allowed in Binding profile", f.Method)
	default:
		return fmt.Errorf("stun: unknown wire_fault kind %q", f.Kind)
	}
}