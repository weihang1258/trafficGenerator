// Package radius implements the RADIUS (RFC 2865/2866) protocol planner.
package radius

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// Default ports (RFC 2865 §3 / RFC 2866 §3). Reference pcaps: auth on
	// 1812 (portion_Radius.pcap), accounting on 1813 (start/stop.pcap).
	PortAuth       = 1812
	PortAccounting = 1813

	// RADIUS codes (RFC 2865 §3, RFC 2866 §3).
	CodeAccessRequest     = 1
	CodeAccessAccept      = 2
	CodeAccessReject      = 3
	CodeAccountingRequest = 4
	CodeAccountingResp    = 5
	CodeAccessChallenge   = 11
	CodeStatusServer      = 12
	CodeStatusClient      = 13

	// Header size: Code(1) + ID(1) + Length(2) + Authenticator(16).
	HeaderLen = 20

	// Attribute length bounds (1-byte Length field).
	MaxAttrValue  = 253 // plain attribute value bytes (Len-2)
	MaxVSAValue   = 247 // Vendor-Specific value bytes (8+value ≤ 255)
	MaxMessageLen = 65535
)

// requestCodes maps valid request-side codes. Response codes 2/5/13 are
// rejected at Validate (they never appear in a request).
var requestCodes = map[int]bool{
	CodeAccessRequest:     true,
	CodeAccessReject:      true,
	CodeAccountingRequest: true,
	CodeAccessChallenge:   true,
	CodeStatusServer:      true,
}

// responseCodes maps valid explicit response codes.
var responseCodes = map[uint8]bool{
	CodeAccessAccept:      true,
	CodeAccessReject:      true,
	CodeAccountingResp:    true,
	CodeAccessChallenge:   true,
	CodeStatusClient:      true,
}

// autoResponse maps request code → default response code (design §5 S3).
var autoResponse = map[int]uint8{
	CodeAccessRequest:     CodeAccessAccept,
	CodeAccountingRequest: CodeAccountingResp,
	CodeStatusServer:      CodeStatusClient,
}

// defaultRequestAttrs returns the design §5 S6 default attribute set for
// a request code (reference-pcap-derived).
func defaultRequestAttrs(code int) []core.RadiusAttribute {
	switch code {
	case CodeAccountingRequest:
		return []core.RadiusAttribute{
			{Type: 40, Format: "uint32", Value: "1"},          // Acct-Status-Type Start
			{Type: 44, Value: "session-0001"},                 // Acct-Session-Id
		}
	default:
		return []core.RadiusAttribute{{Type: 1, Value: "user"}} // User-Name
	}
}

// Planner implements the RADIUS protocol planner.
type Planner struct{}

// NewPlanner creates a new RADIUS planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "radius"
}

// Validate validates a RADIUS flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
	}
	if spec.Radius == nil {
		return fmt.Errorf("radius config is required")
	}
	cfg := spec.Radius

	// Request code (design §7.2): only request-class codes allowed.
	code := cfg.Code
	if code == 0 {
		code = CodeAccessRequest
	}
	if !requestCodes[code] {
		return fmt.Errorf("radius: invalid request code %d (allowed: 1, 3, 4, 11, 12)", code)
	}

	// Response code (design §5 S3): 0 = auto; explicit must be
	// response-class. Codes 3/11 have no auto mapping (they are server
	// replies in real RADIUS), so an explicit response code is required.
	if cfg.ResponseCode != 0 {
		if !responseCodes[cfg.ResponseCode] {
			return fmt.Errorf("radius: invalid response code %d (allowed: 2, 3, 5, 11, 13)", cfg.ResponseCode)
		}
	} else if autoResponse[code] == 0 {
		return fmt.Errorf("radius: code %d has no default response code; set response_code explicitly", code)
	}

	// Fixed authenticator must be valid hex and exactly 16 bytes.
	if cfg.Authenticator != "" {
		b, err := hex.DecodeString(cfg.Authenticator)
		if err != nil {
			return fmt.Errorf("radius: invalid authenticator hex: %v", err)
		}
		if len(b) != 16 {
			return fmt.Errorf("radius: authenticator must be 16 bytes, got %d", len(b))
		}
	}

	// Attribute value lengths (1-byte Length fields, RFC 2865 §5).
	for i, attr := range cfg.Attributes {
		if err := validateRadiusAttribute(attr, "attributes", i); err != nil {
			return err
		}
	}
	for i, attr := range cfg.ResponseAttributes {
		if err := validateRadiusAttribute(attr, "response_attributes", i); err != nil {
			return err
		}
	}
	return nil
}

// validateRadiusAttribute checks format, value encoding, and the Length
// byte bound (plain value ≤253, Vendor-Specific ≤247 so the outer Length
// fits 1 byte). The effective byte length is format-aware: ipv4/uint32 are
// fixed 4 bytes, hex values measure the decoded bytes (the hex string
// itself can be twice as long).
func validateRadiusAttribute(attr core.RadiusAttribute, section string, idx int) error {
	max := MaxAttrValue
	if attr.VendorID > 0 {
		max = MaxVSAValue
	}
	byteLen, err := radiusValueLen(attr)
	if err != nil {
		return fmt.Errorf("radius %s[%d]: %v", section, idx, err)
	}
	if byteLen > max {
		return fmt.Errorf("radius %s[%d]: value length %d exceeds the %d-byte field limit (type %d)", section, idx, byteLen, max, attr.Type)
	}
	switch attr.Format {
	case "", "string":
	case "ipv4":
		ip := net.ParseIP(attr.Value)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("radius %s[%d]: format=ipv4 value %q is not an IPv4 address", section, idx, attr.Value)
		}
	case "uint32":
		if _, err := parseUint32(attr.Value); err != nil {
			return fmt.Errorf("radius %s[%d]: format=uint32 value %q is not a uint32", section, idx, attr.Value)
		}
	case "hex":
		if _, err := hex.DecodeString(attr.Value); err != nil {
			return fmt.Errorf("radius %s[%d]: format=hex value %q is not valid hex", section, idx, attr.Value)
		}
	default:
		return fmt.Errorf("radius %s[%d]: unknown format %q (allowed: string, ipv4, uint32, hex)", section, idx, attr.Format)
	}
	return nil
}

// radiusValueLen returns the encoded value byte length for a format
// (ipv4/uint32 are fixed 4 bytes; hex is len/2 decoded bytes).
func radiusValueLen(attr core.RadiusAttribute) (int, error) {
	switch attr.Format {
	case "", "string":
		return len(attr.Value), nil
	case "ipv4", "uint32":
		return 4, nil
	case "hex":
		b, err := hex.DecodeString(attr.Value)
		if err != nil {
			return 0, fmt.Errorf("format=hex value %q is not valid hex", attr.Value)
		}
		return len(b), nil
	default:
		return 0, fmt.Errorf("unknown format %q", attr.Format)
	}
}

// parseUint32 parses a decimal uint32.
func parseUint32(s string) (uint32, error) {
	var v uint32
	if s == "" {
		return 0, fmt.Errorf("empty uint32")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit %q", string(c))
		}
		d := uint32(c - '0')
		if v > (^uint32(0)-d)/10 {
			return 0, fmt.Errorf("overflow")
		}
		v = v*10 + d
	}
	return v, nil
}

// Plan generates packet configs for a RADIUS flow: Rounds request (up) /
// response (down) exchanges on the same 4-tuple.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := spec.Radius

	// Apply defaults here too: Validate sees a value copy, so defaults
	// applied there are lost for Plan.
	if spec.DstPort == 0 {
		spec.DstPort = PortAuth
		if cfg.Code == CodeAccountingRequest {
			spec.DstPort = PortAccounting
		}
	}
	rounds := cfg.Rounds
	if rounds == 0 {
		rounds = 1
	}
	code := cfg.Code
	if code == 0 {
		code = CodeAccessRequest
	}
	respCode := cfg.ResponseCode
	if respCode == 0 {
		respCode = autoResponse[code]
	}
	reqAttrs := cfg.Attributes
	if len(reqAttrs) == 0 {
		reqAttrs = defaultRequestAttrs(code)
	}

	// Fixed authenticator (hex) or nil → fresh random per round.
	var fixedAuth []byte
	if cfg.Authenticator != "" {
		b, err := hex.DecodeString(cfg.Authenticator)
		if err != nil {
			return nil, fmt.Errorf("radius: invalid authenticator hex: %v", err)
		}
		if len(b) != 16 {
			return nil, fmt.Errorf("radius: authenticator must be 16 bytes, got %d", len(b))
		}
		fixedAuth = b
	}

	// Build the request message once (per-round only the ID/auth change,
	// but rebuilding is trivially cheap; build per round for clarity).
	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		select {
		case <-ctx.Done():
			return
		default:
		}

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		now := time.Now()
		ipID := randomIPID()
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}
		ttl := spec.TTL
		if ttl == 0 {
			ttl = 64
		}
		packetIndex := uint64(0)

		for round := 0; round < rounds; round++ {
			id := byte(cfg.Identifier + uint8(round))

			reqAuth := fixedAuth
			if reqAuth == nil {
				reqAuth = randomAuth()
			}
			reqMsg, err := buildRadiusMessage(byte(code), id, reqAuth, reqAttrs)
			if err != nil {
				// Unreachable after Validate; emit nothing rather than panic.
				return
			}

			select {
			case configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   "up",
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.SrcMAC,
					DstMAC:    spec.DstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(spec.SrcIP, spec.DstIP, 17, ttl, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort:  spec.SrcPort,
					DstPort:  spec.DstPort,
				},
				Payload: reqMsg,
			}:
			case <-ctx.Done():
				return
			}
			packetIndex++

			respMsg, err := buildRadiusMessage(respCode, id, randomAuth(), cfg.ResponseAttributes)
			if err != nil {
				return
			}
			select {
			case configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   "down",
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.DstMAC,
					DstMAC:    spec.SrcMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(spec.DstIP, spec.SrcIP, 17, ttl, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort:  spec.DstPort,
					DstPort:  spec.SrcPort,
				},
				Payload: respMsg,
			}:
			case <-ctx.Done():
				return
			}
			packetIndex++
		}
	}()

	return configChan, nil
}

// buildRadiusMessage assembles one RADIUS message: 20-byte header
// (Code+ID+Length+Authenticator) + encoded attributes. Length =
// 20 + Σ(attribute lengths) (RFC 2865 §3).
func buildRadiusMessage(code, id byte, authenticator []byte, attrs []core.RadiusAttribute) ([]byte, error) {
	body := make([]byte, 0, 64)
	for _, attr := range attrs {
		enc, err := encodeRadiusAttribute(attr)
		if err != nil {
			return nil, err
		}
		body = append(body, enc...)
	}
	total := HeaderLen + len(body)
	if total > MaxMessageLen {
		return nil, fmt.Errorf("radius message length %d exceeds 65535", total)
	}
	msg := make([]byte, HeaderLen, total)
	msg[0] = code
	msg[1] = id
	binary.BigEndian.PutUint16(msg[2:4], uint16(total))
	copy(msg[4:20], authenticator)
	msg = append(msg, body...)
	return msg, nil
}

// encodeRadiusAttribute serializes one attribute (RFC 2865 §5). With
// VendorID > 0 it becomes Vendor-Specific (type 26): outer Len=8+value,
// 4-byte big-endian VendorID, then inner VSA (Type+Len+Value).
func encodeRadiusAttribute(attr core.RadiusAttribute) ([]byte, error) {
	var value []byte
	switch attr.Format {
	case "", "string":
		value = []byte(attr.Value)
	case "ipv4":
		ip := net.ParseIP(attr.Value)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("radius: format=ipv4 value %q is not an IPv4 address", attr.Value)
		}
		value = append([]byte(nil), ip.To4()...)
	case "uint32":
		v, err := parseUint32(attr.Value)
		if err != nil {
			return nil, fmt.Errorf("radius: format=uint32 value %q is not a uint32", attr.Value)
		}
		value = make([]byte, 4)
		binary.BigEndian.PutUint32(value, v)
	case "hex":
		b, err := hex.DecodeString(attr.Value)
		if err != nil {
			return nil, fmt.Errorf("radius: format=hex value %q is not valid hex", attr.Value)
		}
		value = b
	default:
		return nil, fmt.Errorf("radius: unknown attribute format %q", attr.Format)
	}

	if attr.VendorID > 0 {
		if len(value) > MaxVSAValue {
			return nil, fmt.Errorf("radius: VSA value length %d exceeds the %d-byte field limit", len(value), MaxVSAValue)
		}
		// Outer Type=26, outer Len = 8 + inner value length.
		out := make([]byte, 0, 8+len(value))
		out = append(out, 26, byte(8+len(value)))
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], attr.VendorID)
		out = append(out, v[:]...)
		out = append(out, attr.Type, byte(2+len(value)))
		out = append(out, value...)
		return out, nil
	}

	if len(value) > MaxAttrValue {
		return nil, fmt.Errorf("radius: value length %d exceeds the %d-byte field limit", len(value), MaxAttrValue)
	}
	out := make([]byte, 0, 2+len(value))
	out = append(out, attr.Type, byte(2+len(value)))
	out = append(out, value...)
	return out, nil
}

// randomAuth returns 16 random bytes for an Authenticator. crypto/rand
// failure is effectively impossible; fall back to a fixed pattern so the
// flow still emits (pppoe magic-number pattern).
func randomAuth() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		return b
	}
	for i := range b {
		b[i] = byte(0xA5 + i)
	}
	return b
}

// randomIPID returns a random 16-bit IP identification seed.
func randomIPID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint16(b[:])
	}
	return 0x1234
}
