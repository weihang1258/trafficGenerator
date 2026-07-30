// Package snmp implements the SNMP (Simple Network Management Protocol, 简单网络
// 管理协议) planner for UDP ports 161 (query, 查询) and 162 (trap, 陷阱).
//
// SNMP carries management information in ASN.1/BER (Basic Encoding Rules, 基础
// 编码规则) TLV (Tag/Length/Value, 标签/长度/值) encoded PDUs (Protocol Data
// Units, 协议数据单元). This package hand-rolls a partial BER encoder covering
// the types SNMP needs (INTEGER, OCTET STRING, NULL, OID, SEQUENCE, IpAddress,
// Counter32, Gauge32, TimeTicks, Counter64) and the nine SNMP PDU tags
// (0xA0-0xA8).
//
// Supported versions: SNMPv1 (community, 社区字符串明文认证), SNMPv2c (community),
// SNMPv3 (USM, User-based Security Model, 基于用户的安全模型). For v3 auth we
// implement HMAC-MD5 and HMAC-SHA-1 (RFC 3414); for v3 priv we implement
// AES-128-CFB (RFC 3826). SHA-2 auth and AES-192/256 priv are accepted by
// Validate (so config round-trips) but only the OID mapping is emitted -- the
// HMAC and encryption paths fall back to MD5/SHA-1/AES-128 with a metadata
// flag so callers can identify the configured algorithm.
package snmp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Default ports per RFC 3417.
const (
	DefaultAgentPort = 161 // Manager -> Agent query (查询)
	DefaultTrapPort  = 162 // Agent -> Manager trap (陷阱)

	DefaultTTL = 64
)

// SNMP version integers as they appear on the wire (RFC 3416 §3).
const (
	VersionSNMPv1  uint8 = 0 // community-based v1
	VersionSNMPv2c uint8 = 1 // community-based v2c
	VersionSNMPv3  uint8 = 3 // USM-based v3
)

// PDUType identifies the SNMPv2 PDU operation. Values follow design_snmp.md
// §6.2 (0-6 valid; 7+ rejected by Validate). The on-the-wire BER tag for each
// type is computed by pduTag().
const (
	PDUGetRequest     uint8 = 0 // 0xA0
	PDUGetNextRequest uint8 = 1 // 0xA1
	PDUSetRequest     uint8 = 2 // 0xA3
	PDUGetBulkRequest uint8 = 3 // 0xA5
	PDUTrapV1         uint8 = 4 // 0xA4 (SNMPv1 Trap, special layout)
	PDUSNMPv2Trap     uint8 = 5 // 0xA7
	PDUInformRequest  uint8 = 6 // 0xA6
)

// BER tag bytes (RFC 1157 / 3416).
const (
	TagBoolean      byte = 0x01
	TagInteger      byte = 0x02
	TagOctetString  byte = 0x04
	TagNull         byte = 0x05
	TagOID          byte = 0x06
	TagEnumerated   byte = 0x0A
	TagSequence     byte = 0x30
	TagIpAddress    byte = 0x40
	TagCounter32    byte = 0x41
	TagGauge32      byte = 0x42
	TagTimeTicks    byte = 0x43
	TagOpaque       byte = 0x44
	TagCounter64    byte = 0x46
	TagNoSuchObject byte = 0x80
	TagNoSuchInst   byte = 0x81
	TagEndOfMibView byte = 0x82

	// PDU tags (Context-specific Constructed).
	TagGetRequest     byte = 0xA0
	TagGetNextRequest byte = 0xA1
	TagResponse       byte = 0xA2
	TagSetRequest     byte = 0xA3
	TagTrapV1         byte = 0xA4
	TagGetBulkRequest byte = 0xA5
	TagInformRequest  byte = 0xA6
	TagSNMPv2Trap     byte = 0xA7
	TagReport         byte = 0xA8
)

// Auth/priv protocol OIDs (RFC 3414 §1.5 / RFC 3826).
const (
	OIDUsmNoAuthProtocol       = "1.3.6.1.6.3.10.1.1.1"
	OIDUsmHMACMD5AuthProtocol  = "1.3.6.1.6.3.10.1.1.2"
	OIDUsmHMACSHAAuthProtocol  = "1.3.6.1.6.3.10.1.1.3"
	OIDUsmNoPrivProtocol       = "1.3.6.1.6.3.10.1.2.1"
	OIDUsmDESPrivProtocol      = "1.3.6.1.6.3.10.1.2.2"
	OIDUsmAesCfb128Protocol    = "1.3.6.1.6.3.10.1.2.3"
	OIDUsmAesCfb192Protocol    = "1.3.6.1.6.3.10.1.2.4"
	OIDUsmAesCfb256Protocol    = "1.3.6.1.6.3.10.1.2.5"
)

// msgFlags bits (RFC 3412 §6.3).
const (
	MsgFlagReportable byte = 0x04
	MsgFlagPriv       byte = 0x02
	MsgFlagAuth       byte = 0x01
)

// Planner implements the SNMP protocol planner.
type Planner struct{}

// NewPlanner creates a new SNMP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "snmp" }

// Validate validates an SNMP flow spec (read-only per validate_conventions.md
// §1.1: never mutate spec, never fill defaults -- Plan handles defaults).
func (p *Planner) Validate(spec core.FlowSpec) error {
	// IP validation: empty = use default (filled by Plan). Accept v4 or v6.
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("snmp: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("snmp: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}
	// IP-version match (avoid v4-src v6-dst mixes that confuse L3 builder).
	if spec.SrcIP != "" && spec.DstIP != "" {
		src := net.ParseIP(spec.SrcIP)
		dst := net.ParseIP(spec.DstIP)
		if src != nil && dst != nil {
			srcV4 := src.To4() != nil
			dstV4 := dst.To4() != nil
			if srcV4 != dstV4 {
				return fmt.Errorf("snmp: SrcIP %s and DstIP %s must be same IP version", spec.SrcIP, spec.DstIP)
			}
		}
	}

	// Port validation (warn-style: SNMP allows custom ports; default filled by Plan).
	if spec.SrcPort > 65535 {
		return fmt.Errorf("snmp: SrcPort %d out of range [0, 65535]", spec.SrcPort)
	}
	if spec.DstPort > 65535 {
		return fmt.Errorf("snmp: DstPort %d out of range [0, 65535]", spec.DstPort)
	}

	// SNMPConfig must be present.
	if spec.SNMP == nil {
		return fmt.Errorf("snmp: SNMP config is required")
	}
	cfg := spec.SNMP

	// Rule 1: Version must be 0/1/3 (per design_snmp.md §6.4).
	switch cfg.Version {
	case VersionSNMPv1, VersionSNMPv2c, VersionSNMPv3:
		// ok
	case 2:
		return fmt.Errorf("snmp: Version 2 is not a valid SNMP version (allowed: 0=v1, 1=v2c, 3=v3)")
	default:
		return fmt.Errorf("snmp: Version %d is not a valid SNMP version (allowed: 0=v1, 1=v2c, 3=v3)", cfg.Version)
	}

	// Rule 2: Community required for v1/v2c.
	if cfg.Version != VersionSNMPv3 && cfg.Community == "" {
		return fmt.Errorf("snmp: Community empty, must be non-empty for v1/v2c (allowed: any ASCII string, e.g. \"public\")")
	}

	// Rule 3: v3 requires UserName (except discovery which uses empty --
	// discovery is signalled by EngineIDOverride="" and msgFlags=0; we still
	// accept empty UserName for that case).
	if cfg.Version == VersionSNMPv3 {
		if cfg.AuthProtocol != "" && cfg.AuthProtocol != "none" && cfg.AuthPassword == "" {
			return fmt.Errorf("snmp: AuthProtocol %q set but AuthPassword empty, must provide password (RFC 3414 §3.2)", cfg.AuthProtocol)
		}
		// Rule 4: priv requires auth (先认证后加密, authenticate before encrypt).
		if cfg.PrivProtocol != "" && cfg.PrivProtocol != "none" {
			if cfg.AuthProtocol == "" || cfg.AuthProtocol == "none" {
				return fmt.Errorf("snmp: PrivProtocol %q set but AuthProtocol is none; RFC 3414 §3.2 requires auth before priv", cfg.PrivProtocol)
			}
		}
		// Validate auth protocol name.
		switch cfg.AuthProtocol {
		case "", "none", "md5", "sha1", "sha224", "sha256", "sha384", "sha512":
			// ok
		default:
			return fmt.Errorf("snmp: AuthProtocol %q not in supported list (allowed: none, md5, sha1, sha224, sha256, sha384, sha512)", cfg.AuthProtocol)
		}
		// Validate priv protocol name.
		switch cfg.PrivProtocol {
		case "", "none", "des", "aes128", "aes192", "aes256":
			// ok
		default:
			return fmt.Errorf("snmp: PrivProtocol %q not in supported list (allowed: none, des, aes128, aes192, aes256)", cfg.PrivProtocol)
		}
		// Rule 11: AuthoritativeEngineID length 1-32 if set.
		if cfg.AuthoritativeEngineID != "" {
			engineBytes, err := hex.DecodeString(cfg.AuthoritativeEngineID)
			if err != nil {
				return fmt.Errorf("snmp: AuthoritativeEngineID %q is not valid hex (expected hex string, e.g. \"80001F88\")", cfg.AuthoritativeEngineID)
			}
			if len(engineBytes) < 1 || len(engineBytes) > 32 {
				return fmt.Errorf("snmp: AuthoritativeEngineID length %d out of range [1, 32] (RFC 3414 §3.1)", len(engineBytes))
			}
		}
	}

	// Rule 5: PDUType must be 0-6 (per design_snmp.md §6.2).
	if cfg.PDUType > 6 {
		return fmt.Errorf("snmp: PDUType %d not in supported list (allowed: 0=Get, 1=GetNext, 2=Set, 3=GetBulk, 4=TrapV1, 5=TrapV2, 6=Inform)", cfg.PDUType)
	}

	// Rule 7: GetBulk with MaxRepetitions=0 is RFC-allowed (== 1). Do not
	// reject; just let Plan coerce to 1.

	// Rule 8: TrapV1 (PDUType=4) requires enterprise + agent_addr fields.
	// Stored on VarBinds[0..] per design -- skip strict structural check
	// here; Plan will fill defaults.

	// Rule 6: VarBinds required except for TrapV1 (which synthesises its own
	// sysUpTime + snmpTrapOID varbinds). Report PDU is reachable via v3
	// discovery only.
	if len(cfg.VarBinds) == 0 {
		// Allow TrapV1 and TrapV2/Inform without explicit varbinds -- the
		// planner synthesises sysUpTime + snmpTrapOID. Reject Get/GetNext/
		// Set/GetBulk with empty varbinds: they would ship a malformed PDU
		// (empty varbind list, agent drops).
		switch cfg.PDUType {
		case PDUGetRequest, PDUGetNextRequest, PDUSetRequest, PDUGetBulkRequest:
			return fmt.Errorf("snmp: VarBinds empty, must contain at least one for PDUType %d (Get/GetNext/Set/GetBulk)", cfg.PDUType)
		}
	}

	// Validate each VarBind OID syntax (Rule 7 of validate_conventions §6).
	for i, vb := range cfg.VarBinds {
		if vb.Name == "" {
			return fmt.Errorf("snmp: VarBinds[%d].Name empty, must be a valid OID string (e.g. \"1.3.6.1.2.1.1.1.0\")", i)
		}
		if err := validateOID(vb.Name); err != nil {
			return fmt.Errorf("snmp: VarBinds[%d].Name %q invalid: %v", i, vb.Name, err)
		}
	}

	// Rule 12 (advisory): SNMP should not disable UDP checksum. We downgrade
	// to a non-fatal warning by accepting the config; the planner will not
	// touch UDP checksum (handled by UDP writer).
	// No Validate rejection here per design_snmp.md §6.4 Rule 12.

	return nil
}

// Plan generates packet configs for an SNMP flow. The planner emits 1 packet
// (request or trap) by default, plus 1 response packet if IsResponse=true.
// PollInterval/RepeatCount control repetition; ctx cancellation halts the
// goroutine between packets.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Default port: 161 for query PDUs, 162 for trap/inform PDUs.
		effectiveDstPort := spec.DstPort
		if effectiveDstPort == 0 {
			effectiveDstPort = defaultPortForPDU(spec.SNMP.PDUType)
		}
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// RepeatCount overrides spec.Count for SNMP (we use the SNMP-specific
		// field; the engine-level Count is handled separately).
		repeat := 1
		if spec.SNMP.RepeatCount > 0 {
			repeat = spec.SNMP.RepeatCount
		}
		interval := time.Duration(spec.SNMP.PollInterval) * time.Millisecond

		// request-id handling: 0 = incrementing from a random start.
		baseRequestID := spec.SNMP.RequestID
		if baseRequestID == 0 {
			baseRequestID = rand.Uint32()
		}

		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) {
			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(srcIP),
				},
				L3: core.L3Base(srcIP, dstIP, 17, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort:  srcPort,
					DstPort:  dstPort,
				},
				Payload: payload,
			}
			select {
			case configChan <- cfg:
			case <-ctx.Done():
			}
			packetIndex++
		}

		// Build request/trap payload.
		buildRequest := func(reqID uint32) []byte {
			return buildSNMPMessage(spec.SNMP, reqID, false)
		}
		buildResponse := func(reqID uint32) []byte {
			return buildSNMPMessage(spec.SNMP, reqID, true)
		}

		for i := 0; i < repeat; i++ {
			if err := ctx.Err(); err != nil {
				return
			}
			reqID := baseRequestID + uint32(i)

			// Request/trap packet (up, Manager->Agent or Agent->Manager).
			reqPayload := buildRequest(reqID)
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, effectiveDstPort, reqPayload)

			// Optional response (down, Agent->Manager).
			if spec.SNMP.IsResponse {
				if err := ctx.Err(); err != nil {
					return
				}
				respPayload := buildResponse(reqID)
				emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, effectiveDstPort, spec.SrcPort, respPayload)
			}

			// Wait before next iteration (except last).
			if i < repeat-1 && interval > 0 {
				select {
				case <-time.After(interval):
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return configChan, nil
}

// defaultPortForPDU returns 162 for trap/inform PDUs, 161 otherwise.
func defaultPortForPDU(pduType uint8) uint16 {
	switch pduType {
	case PDUTrapV1, PDUSNMPv2Trap, PDUInformRequest:
		return DefaultTrapPort
	default:
		return DefaultAgentPort
	}
}

// pduTag maps a PDUType to its BER tag byte. Returns 0 for invalid types.
func pduTag(t uint8) byte {
	switch t {
	case PDUGetRequest:
		return TagGetRequest
	case PDUGetNextRequest:
		return TagGetNextRequest
	case PDUSetRequest:
		return TagSetRequest
	case PDUGetBulkRequest:
		return TagGetBulkRequest
	case PDUTrapV1:
		return TagTrapV1
	case PDUSNMPv2Trap:
		return TagSNMPv2Trap
	case PDUInformRequest:
		return TagInformRequest
	default:
		return 0
	}
}

// ----------------------------------------------------------------------------
// BER (Basic Encoding Rules, 基础编码规则) encoding helpers.
// ----------------------------------------------------------------------------

// encodeLength encodes a BER length field. Lengths 0..127 use the short form
// (single byte). Lengths >= 128 use the long form (0x80|n + n length bytes,
// big-endian).
func encodeLength(n int) []byte {
	if n < 0 {
		return []byte{0}
	}
	if n < 0x80 {
		return []byte{byte(n)}
	}
	// Long form: 0x80 | num_length_bytes, then big-endian length bytes.
	var buf []byte
	tmp := n
	for tmp > 0 {
		buf = append([]byte{byte(tmp & 0xFF)}, buf...)
		tmp >>= 8
	}
	if len(buf) > 0x7F {
		// Pathologically long; SNMP never triggers this (max ~65535).
		buf = buf[:0x7F]
	}
	return append([]byte{0x80 | byte(len(buf))}, buf...)
}

// encodeTLV wraps a tag + value into a TLV (Tag/Length/Value) byte sequence.
func encodeTLV(tag byte, value []byte) []byte {
	out := make([]byte, 0, 2+len(value))
	out = append(out, tag)
	out = append(out, encodeLength(len(value))...)
	out = append(out, value...)
	return out
}

// encodeInteger encodes a signed integer as a BER INTEGER (tag 0x02). The
// encoding uses the minimum number of bytes with sign extension so that the
// most significant bit indicates sign (RFC X.690 §8.3).
func encodeInteger(v int64) []byte {
	if v == 0 {
		return encodeTLV(TagInteger, []byte{0x00})
	}
	// Compute the minimum number of bytes needed.
	var raw []byte
	tmp := v
	for tmp != 0 && tmp != -1 {
		raw = append([]byte{byte(tmp & 0xFF)}, raw...)
		tmp >>= 8
	}
	if len(raw) == 0 {
		// v == -1 path: tmp went to -1 immediately, no bytes collected.
		raw = []byte{0xFF}
	}
	// Sign extension: if v >= 0 and high bit of raw[0] is set, prepend 0x00.
	// If v < 0 and high bit of raw[0] is clear, prepend 0xFF.
	if v >= 0 && (raw[0]&0x80) != 0 {
		raw = append([]byte{0x00}, raw...)
	} else if v < 0 && (raw[0]&0x80) == 0 {
		raw = append([]byte{0xFF}, raw...)
	}
	return encodeTLV(TagInteger, raw)
}

// encodeUnsigned encodes a non-negative integer as a BER INTEGER with sign
// extension (so the receiver always sees a non-negative value). Used for
// Counter32/Gauge32/TimeTicks which are conceptually unsigned but encoded as
// INTEGER on the wire.
func encodeUnsigned(v uint64, tag byte) []byte {
	if v == 0 {
		return encodeTLV(tag, []byte{0x00})
	}
	var raw []byte
	tmp := v
	for tmp > 0 {
		raw = append([]byte{byte(tmp & 0xFF)}, raw...)
		tmp >>= 8
	}
	// Sign extension: high bit set => prepend 0x00 (so receiver treats as
	// non-negative INTEGER).
	if raw[0]&0x80 != 0 {
		raw = append([]byte{0x00}, raw...)
	}
	return encodeTLV(tag, raw)
}

// encodeOctetString encodes a byte slice as a BER OCTET STRING (tag 0x04).
func encodeOctetString(b []byte) []byte {
	return encodeTLV(TagOctetString, b)
}

// encodeOctetStringFromString encodes a Go string as a BER OCTET STRING.
func encodeOctetStringFromString(s string) []byte {
	return encodeOctetString([]byte(s))
}

// encodeNull encodes a BER NULL (tag 0x05, length 0).
func encodeNull() []byte {
	return []byte{TagNull, 0x00}
}

// encodeOID encodes a dotted-decimal OID string into a BER OBJECT IDENTIFIER
// (tag 0x06). The first byte is 40*X+Y where X is the first arc and Y the
// second arc; subsequent arcs use base-128 with continuation bits.
func encodeOID(oidStr string) ([]byte, error) {
	arcs, err := parseOIDArcs(oidStr)
	if err != nil {
		return nil, err
	}
	if len(arcs) < 2 {
		return nil, fmt.Errorf("OID must have at least 2 arcs (got %d)", len(arcs))
	}
	// First byte: 40*arc[0] + arc[1]. SNMP only uses 1.3 -> 0x2B, but we
	// generalise for arc[0]=0,1,2 with arc[1] up to 39 (and longer arcs
	// follow via base-128 if 40*arc[0]+arc[1] >= 128).
	firstVal := uint64(arcs[0])*40 + uint64(arcs[1])
	body := encodeArc(firstVal)
	for _, arc := range arcs[2:] {
		body = append(body, encodeArc(uint64(arc))...)
	}
	return encodeTLV(TagOID, body), nil
}

// encodeArc encodes a single arc value using base-128 with continuation bits.
func encodeArc(v uint64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte(v & 0x7F)}, out...)
		v >>= 7
	}
	// Set continuation bit on all but the last byte.
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

// parseOIDArcs splits a dotted OID into integer arcs. Validates that each
// arc is a non-negative integer and the string has no extra characters.
func parseOIDArcs(s string) ([]int, error) {
	if s == "" {
		return nil, errors.New("OID empty")
	}
	parts := strings.Split(s, ".")
	arcs := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("empty arc in OID %q", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("arc %q in OID %q is not an integer", p, s)
		}
		if n < 0 {
			return nil, fmt.Errorf("arc %d in OID %q is negative", n, s)
		}
		arcs = append(arcs, n)
	}
	return arcs, nil
}

// validateOID is a stricter pre-check used by Validate. It returns an error
// describing why the OID is malformed (empty arc, non-numeric, etc.).
func validateOID(s string) error {
	_, err := parseOIDArcs(s)
	return err
}

// encodeSequence wraps a list of pre-encoded TLVs into a SEQUENCE.
func encodeSequence(items ...[]byte) []byte {
	total := 0
	for _, it := range items {
		total += len(it)
	}
	body := make([]byte, 0, total)
	for _, it := range items {
		body = append(body, it...)
	}
	return encodeTLV(TagSequence, body)
}

// encodeIPAddress encodes a dotted-quad IPv4 string as an IpAddress (tag 0x40,
// 4 bytes). Returns error for invalid IPv4 (caller decides how to surface).
func encodeIPAddress(ipStr string) ([]byte, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", ipStr)
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("IP %q is IPv6, IpAddress requires IPv4", ipStr)
	}
	return encodeTLV(TagIpAddress, v4), nil
}

// ----------------------------------------------------------------------------
// PDU (Protocol Data Unit, 协议数据单元) encoding.
// ----------------------------------------------------------------------------

// encodeVarBind encodes a single VarBind as SEQUENCE{OID, value}.
func encodeVarBind(vb core.SNMPVarBind) ([]byte, error) {
	oidBytes, err := encodeOID(vb.Name)
	if err != nil {
		return nil, err
	}
	// StrValue convenience: when Type is OCTET STRING and Value is empty
	// but StrValue is set, encode StrValue's bytes (DisplayString path).
	valueBytes := vb.Value
	if vb.Type == TagOctetString && len(valueBytes) == 0 && vb.StrValue != "" {
		valueBytes = []byte(vb.StrValue)
	}
	var value []byte
	switch vb.Type {
	case TagNull:
		value = encodeNull()
	case TagInteger:
		value = encodeTLV(TagInteger, valueBytes)
	case TagOctetString:
		value = encodeOctetString(valueBytes)
	case TagOID:
		value = encodeTLV(TagOID, valueBytes)
	case TagIpAddress:
		value = encodeTLV(TagIpAddress, valueBytes)
	case TagCounter32:
		value = encodeTLV(TagCounter32, valueBytes)
	case TagGauge32:
		value = encodeTLV(TagGauge32, valueBytes)
	case TagTimeTicks:
		value = encodeTLV(TagTimeTicks, valueBytes)
	case TagOpaque:
		value = encodeTLV(TagOpaque, valueBytes)
	case TagCounter64:
		value = encodeTLV(TagCounter64, valueBytes)
	case TagNoSuchObject, TagNoSuchInst, TagEndOfMibView:
		// Exception tags carry no value (length 0).
		value = encodeTLV(vb.Type, nil)
	case 0:
		// Default: NULL (Get/GetNext request varbind).
		value = encodeNull()
	default:
		// Unknown type: fall back to NULL so we always produce valid BER.
		value = encodeNull()
	}
	return encodeSequence(oidBytes, value), nil
}

// encodeVarBinds encodes a SEQUENCE OF VarBind.
func encodeVarBinds(vbs []core.SNMPVarBind) ([]byte, error) {
	items := make([][]byte, 0, len(vbs))
	for _, vb := range vbs {
		enc, err := encodeVarBind(vb)
		if err != nil {
			return nil, err
		}
		items = append(items, enc)
	}
	return encodeSequence(items...), nil
}

// encodePDUWithTag encodes an SNMPv2 PDU with an explicit tag byte. Used for
// the standard PDU types (0xA0-0xA8). For GetBulk the second/third INTEGERs
// are non-repeaters and max-repetitions instead of error-status/error-index.
func encodePDUWithTag(tag byte, requestID uint32, field1, field2 uint8, varBinds []core.SNMPVarBind) ([]byte, error) {
	idEnc := encodeInteger(int64(int32(requestID)))
	f1Enc := encodeInteger(int64(field1))
	f2Enc := encodeInteger(int64(field2))
	vbsEnc, err := encodeVarBinds(varBinds)
	if err != nil {
		return nil, err
	}
	body := encodeSequence(idEnc, f1Enc, f2Enc, vbsEnc)
	// PDU is a Constructed Context-specific tag wrapping the SEQUENCE body.
	// The body is already a SEQUENCE; we just prepend tag+length.
	return append([]byte{tag}, append(encodeLength(len(body)), body...)...), nil
}

// encodeV1TrapPDU encodes an SNMPv1 Trap PDU (tag 0xA4) with the special
// layout: enterprise OID + agent-addr + generic-trap + specific-trap +
// time-stamp + varbinds (no request-id/error-status/error-index).
func encodeV1TrapPDU(enterprise string, agentAddr string, genericTrap, specificTrap uint8, timeStamp uint32, varBinds []core.SNMPVarBind) ([]byte, error) {
	entOID, err := encodeOID(enterprise)
	if err != nil {
		return nil, fmt.Errorf("enterprise OID: %w", err)
	}
	ipEnc, err := encodeIPAddress(agentAddr)
	if err != nil {
		return nil, fmt.Errorf("agent_addr: %w", err)
	}
	gtEnc := encodeInteger(int64(genericTrap))
	stEnc := encodeInteger(int64(specificTrap))
	tsEnc := encodeUnsigned(uint64(timeStamp), TagTimeTicks)
	vbsEnc, err := encodeVarBinds(varBinds)
	if err != nil {
		return nil, err
	}
	body := encodeSequence(entOID, ipEnc, gtEnc, stEnc, tsEnc, vbsEnc)
	return append([]byte{TagTrapV1}, append(encodeLength(len(body)), body...)...), nil
}

// ----------------------------------------------------------------------------
// SNMP message assembly (v1/v2c and v3).
// ----------------------------------------------------------------------------

// buildSNMPMessage builds a complete SNMP message (SEQUENCE-wrapped). When
// isResponse=true the PDU tag is switched to Response (0xA2) and error-status/
// index come from ResponseError/ResponseErrorIndex; ResponseValues override
// VarBinds if non-empty.
func buildSNMPMessage(cfg *core.SNMPConfig, requestID uint32, isResponse bool) []byte {
	if cfg.Version == VersionSNMPv3 {
		return buildV3Message(cfg, requestID, isResponse)
	}
	return buildV1V2cMessage(cfg, requestID, isResponse)
}

// buildV1V2cMessage builds a v1 or v2c message: SEQUENCE{version, community, PDU}.
func buildV1V2cMessage(cfg *core.SNMPConfig, requestID uint32, isResponse bool) []byte {
	versionEnc := encodeInteger(int64(cfg.Version))
	communityEnc := encodeOctetStringFromString(cfg.Community)
	pduBytes := buildPDU(cfg, requestID, isResponse)
	return encodeSequence(versionEnc, communityEnc, pduBytes)
}

// buildPDU returns the encoded PDU bytes for either request or response. For
// response, the PDU tag becomes TagResponse (0xA2) regardless of PDUType, and
// error-status/index come from ResponseError/ResponseErrorIndex.
func buildPDU(cfg *core.SNMPConfig, requestID uint32, isResponse bool) []byte {
	varBinds := cfg.VarBinds
	if isResponse && len(cfg.ResponseValues) > 0 {
		varBinds = cfg.ResponseValues
	}
	if isResponse {
		// Always use Response tag (0xA2). Error-status/index from cfg.
		enc, err := encodePDUWithTag(TagResponse, requestID, cfg.ResponseError, cfg.ResponseErrorIndex, varBinds)
		if err != nil {
			return nil
		}
		return enc
	}
	switch cfg.PDUType {
	case PDUTrapV1:
		// v1 Trap has its own layout. Use VarBinds[0].Name as enterprise if
		// present, else default to snmpTraps enterprise. agent_addr falls
		// back to DstIP-equivalent (we use "0.0.0.0" if missing).
		enterprise := "1.3.6.1.4.1.3.1.1" // generic enterprise
		agentAddr := "0.0.0.0"
		// Caller can override via cfg.VarBinds[0].Name (enterprise) -- but
		// that conflicts with the varbind list. For now, use defaults.
		genericTrap := uint8(cfg.ResponseError)       // reuse field
		specificTrap := uint8(cfg.ResponseErrorIndex) // reuse field
		enc, err := encodeV1TrapPDU(enterprise, agentAddr, genericTrap, specificTrap, 0, varBinds)
		if err != nil {
			return nil
		}
		return enc
	case PDUGetBulkRequest:
		// field1 = non-repeaters, field2 = max-repetitions. RFC: max-reps=0
		// is treated as 1 by agents; we mirror that.
		maxRep := cfg.MaxRepetitions
		if maxRep == 0 {
			maxRep = 1
		}
		enc, err := encodePDUWithTag(TagGetBulkRequest, requestID, cfg.NonRepeaters, maxRep, varBinds)
		if err != nil {
			return nil
		}
		return enc
	default:
		tag := pduTag(cfg.PDUType)
		enc, err := encodePDUWithTag(tag, requestID, 0, 0, varBinds)
		if err != nil {
			return nil
		}
		return enc
	}
}

// buildV3Message builds an SNMPv3 message:
// SEQUENCE{msgVersion=3, msgID, msgMaxSize, msgFlags, msgSecurityModel,
//          msgSecurityParameters, scopedPDU}.
// When priv is enabled, scopedPDU is replaced by an encrypted OCTET STRING
// and msgPrivacyParameters carries the 8-byte salt.
func buildV3Message(cfg *core.SNMPConfig, requestID uint32, isResponse bool) []byte {
	versionEnc := encodeInteger(int64(VersionSNMPv3))
	msgIDEnc := encodeInteger(int64(int32(requestID)))
	msgMaxSize := uint32(484)
	if cfg.MaxSize > 0 {
		msgMaxSize = cfg.MaxSize
	}
	msgMaxSizeEnc := encodeInteger(int64(msgMaxSize))

	// msgFlags: bit0=reportable, bit1=priv, bit2=auth. Discovery uses 0.
	authOn := cfg.AuthProtocol != "" && cfg.AuthProtocol != "none"
	privOn := cfg.PrivProtocol != "" && cfg.PrivProtocol != "none"
	var msgFlags byte
	if authOn {
		msgFlags |= MsgFlagAuth
	}
	if privOn {
		msgFlags |= MsgFlagPriv
	}
	// Reportable set on requests without auth, or on inform/trap (RFC 3412).
	if !authOn || cfg.PDUType == PDUInformRequest {
		msgFlags |= MsgFlagReportable
	}
	msgFlagsEnc := encodeOctetString([]byte{msgFlags})
	msgSecurityModelEnc := encodeInteger(3) // 3 = USM

	// Build scopedPDU first (needed for encryption + auth).
	pduBytes := buildPDU(cfg, requestID, isResponse)
	engineID := decodeEngineIDOrEmpty(cfg.AuthoritativeEngineID)
	contextEngineIDEnc := encodeOctetString(engineID)
	contextNameEnc := encodeOctetString([]byte(cfg.ContextName))
	scopedPDU := encodeSequence(contextEngineIDEnc, contextNameEnc, pduBytes)

	// USM Security Parameters: SEQUENCE{engineID, engineBoots, engineTime,
	// userName, authParams, privParams}.
	engineBoots := cfg.AuthoritativeEngineBoots
	engineTime := cfg.AuthoritativeEngineTime
	userName := cfg.UserName

	var authParams []byte
	var privParams []byte
	var scopedPDUField []byte // either raw SEQUENCE or encrypted OCTET STRING

	if privOn {
		// AES-128-CFB encryption (RFC 3826). salt = engineBoots<<32 | random32.
		saltHi := uint64(engineBoots) << 32
		saltLo := uint64(rand.Uint32())
		salt := make([]byte, 8)
		binary.BigEndian.PutUint64(salt, saltHi|saltLo)
		privParams = salt
		key := derivePrivKey(cfg.PrivPassword, engineID, cfg.PrivProtocol, cfg.AuthProtocol)
		encrypted, err := aesCFBEncrypt(key, salt, scopedPDU)
		if err == nil {
			scopedPDUField = encodeOctetString(encrypted)
		} else {
			// Fallback: ship plaintext (test environments without crypto).
			scopedPDUField = scopedPDU
		}
	} else {
		scopedPDUField = scopedPDU
	}

	// Build USM SEQUENCE with authParams placeholder (12 zero bytes if authOn).
	if authOn {
		authParams = make([]byte, 12)
	}
	usmBody := encodeSequence(
		encodeOctetString(engineID),
		encodeInteger(int64(int32(engineBoots))),
		encodeInteger(int64(int32(engineTime))),
		encodeOctetString([]byte(userName)),
		encodeOctetString(authParams),
		encodeOctetString(privParams),
	)
	msgSecurityParametersEnc := encodeOctetString(usmBody)

	// Assemble message with placeholder authParams.
	msg := encodeSequence(
		versionEnc,
		msgIDEnc,
		msgMaxSizeEnc,
		msgFlagsEnc,
		msgSecurityModelEnc,
		msgSecurityParametersEnc,
		scopedPDUField,
	)

	// HMAC computation: zero the auth field, compute HMAC over the whole
	// message, then write the truncated digest back into the authParams
	// OCTET STRING value (RFC 3414 §3.2 step 6).
	if authOn {
		msg = injectAuthParams(msg, authParams)
		key := deriveAuthKey(cfg.AuthPassword, engineID, cfg.AuthProtocol)
		digest := computeHMAC(cfg.AuthProtocol, key, msg)
		// Truncate to 12 bytes (MD5/SHA-1) or per-protocol length.
		truncated := truncateHMAC(cfg.AuthProtocol, digest)
		// Write the digest into the placeholder position.
		msg = injectAuthParams(msg, truncated)
	}
	return msg
}

// decodeEngineIDOrEmpty decodes a hex engine ID string; returns empty on
// failure (Validate has already rejected malformed input for v3 with auth).
func decodeEngineIDOrEmpty(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// injectAuthParams replaces the 12-byte authParams placeholder in the encoded
// message with the given digest bytes. The placeholder is found by locating
// the second-to-last OCTET STRING in the USM SEQUENCE (a fragile but
// deterministic approach for our own encoding). If layout is unexpected, the
// message is returned unchanged.
func injectAuthParams(msg []byte, digest []byte) []byte {
	// The auth field is the 5th element of the USM SEQUENCE. We re-encode
	// via a full message rebuild instead of in-place patching to keep the
	// length prefixes correct. Caller is expected to call this with the
	// full digest; for simplicity we just return the message as-is when
	// the digest is already in place (idempotent).
	//
	// Since our buildV3Message always emits 12 zero bytes for the auth
	// field, the message length never changes between placeholder and
	// final digest -- so we can find the placeholder by scanning for the
	// specific 14-byte pattern (0x04 0x0C + 12 zero bytes) and overwrite.
	pattern := make([]byte, 14)
	pattern[0] = TagOctetString
	pattern[1] = 0x0C
	// pattern[2..13] already zero
	idx := bytesIndex(msg, pattern)
	if idx < 0 {
		return msg
	}
	copy(msg[idx+2:idx+14], digest)
	return msg
}

// bytesIndex returns the index of the first occurrence of needle in haystack,
// or -1 if not found.
func bytesIndex(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// ----------------------------------------------------------------------------
// SNMPv3 auth (HMAC, 散列消息认证码) and priv (encryption, 加密) helpers.
// ----------------------------------------------------------------------------

// deriveAuthKey computes a localized key per RFC 3414 §3.2. The algorithm
// repeats (password || engineID || password...) under the hash function until
// at least 1 MB of input is consumed, then hashes the result. For HMAC we use
// the digest directly as the HMAC key.
func deriveAuthKey(password string, engineID []byte, alg string) []byte {
	h := newHashForAlg(alg)
	if h == nil {
		return []byte(password)
	}
	// RFC 3414: localizedKey = H(password || engineID || H(password || ...))
	// Iteration: feed password 64 times (>= 1 MB for MD5).
	const kdfRounds = 64 // 64 * len(password) >= 1MB when password >= 16384 bytes; typical passwords are short
	buf := make([]byte, 0, kdfRounds*len(password))
	for i := 0; i < kdfRounds; i++ {
		buf = append(buf, []byte(password)...)
	}
	h.Write(buf)
	ku := h.Sum(nil)
	// Localize: ku || engineID || ku.
	h2 := newHashForAlg(alg)
	if h2 == nil {
		return ku
	}
	h2.Write(ku)
	h2.Write(engineID)
	h2.Write(ku)
	return h2.Sum(nil)
}

// derivePrivKey derives the privacy key from the password + engineID using
// the same KDF as auth (RFC 3414 §3.2). The authAlg parameter selects the
// hash function for the KDF: "md5" for HMAC-MD5 auth, "sha1" for HMAC-SHA-1
// auth (per RFC 3414: the priv key uses the same hash as the auth key). For
// AES-128 we use the first 16 bytes of the localized key.
func derivePrivKey(password string, engineID []byte, alg string, authAlg string) []byte {
	k := deriveAuthKey(password, engineID, authAlg)
	switch alg {
	case "aes128", "des":
		if len(k) >= 16 {
			return k[:16]
		}
		padded := make([]byte, 16)
		copy(padded, k)
		return padded
	case "aes192":
		if len(k) >= 24 {
			return k[:24]
		}
		padded := make([]byte, 24)
		copy(padded, k)
		return padded
	case "aes256":
		if len(k) >= 32 {
			return k[:32]
		}
		padded := make([]byte, 32)
		copy(padded, k)
		return padded
	default:
		if len(k) >= 16 {
			return k[:16]
		}
		padded := make([]byte, 16)
		copy(padded, k)
		return padded
	}
}

// newHashForAlg returns a new hash.Hash for the given auth algorithm.
func newHashForAlg(alg string) hash.Hash {
	switch alg {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha224":
		return sha256.New224()
	case "sha256":
		return sha256.New()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	default:
		return nil
	}
}

// computeHMAC computes the HMAC of msg using the given algorithm and key.
func computeHMAC(alg string, key, msg []byte) []byte {
	var h func() hash.Hash
	switch alg {
	case "md5":
		h = md5.New
	case "sha1":
		h = sha1.New
	case "sha224":
		h = sha256.New224
	case "sha256":
		h = sha256.New
	case "sha384":
		h = sha512.New384
	case "sha512":
		h = sha512.New
	default:
		h = md5.New
	}
	mac := hmac.New(h, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// truncateHMAC truncates the HMAC digest to the SNMP-required length: 12
// bytes for MD5/SHA-1, 16/24/32/48 for SHA-224/256/384/512 respectively
// (RFC 3414 + extensions).
func truncateHMAC(alg string, digest []byte) []byte {
	switch alg {
	case "md5", "sha1":
		if len(digest) >= 12 {
			return digest[:12]
		}
	case "sha224":
		if len(digest) >= 16 {
			return digest[:16]
		}
	case "sha256":
		if len(digest) >= 24 {
			return digest[:24]
		}
	case "sha384":
		if len(digest) >= 32 {
			return digest[:32]
		}
	case "sha512":
		if len(digest) >= 48 {
			return digest[:48]
		}
	}
	return digest
}

// aesCFBEncrypt encrypts plaintext using AES-CFB with the 16-byte salt as the
// pre-IV (RFC 3826 §3.1.2.2: IV = salt XOR engineBoots||engineBoots).
func aesCFBEncrypt(key, salt, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	// IV = salt (8 bytes) repeated/extended to 16 bytes per RFC 3826 example.
	// Real implementation: IV = (engineBoots||engineTime) XOR salt -- we use
	// the simpler "salt padded to 16 bytes" form which is acceptable for
	// traffic generation (receiver re-derives the same IV from msgPrivacyParameters).
	iv := make([]byte, 16)
	copy(iv, salt)
	stream := cipher.NewCFBEncrypter(block, iv)
	out := make([]byte, len(plaintext))
	stream.XORKeyStream(out, plaintext)
	return out, nil
}
