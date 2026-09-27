package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

type BGPConfig = core.BGPConfig

const (
	defaultVersion    = 4
	defaultASN        = 64512
	defaultIdentifier = "192.0.2.1"
	defaultProfile    = "bgp_rfc4271_ipv4_unicast"
	bgpHeaderLen      = 19
	bgpMaxLen         = 4096
)

// BGP message types (RFC 4271 §4).
const (
	msgOpen         = 1
	msgUpdate       = 2
	msgNotification = 3
	msgKeepalive    = 4
)

// BGP path attribute type codes and flags (RFC 4271 §4.3 / §5).
const (
	attrOrigin         = 1
	attrASPath         = 2
	attrNextHop        = 3
	attrMultiExit      = 4
	attrLocalPref      = 5
	attrCommunities    = 8
	flagTransitive     = 0x40
	flagOptional       = 0x80
	flagOptionalTrans  = 0xc0
	asSequence         = 2
	communityWellKnown = 0xffffff01 // NO_EXPORT
)

func normalized(c *BGPConfig) BGPConfig {
	v := *c
	if v.Version == 0 {
		v.Version = defaultVersion
	}
	if v.ASN == 0 {
		v.ASN = defaultASN
	}
	if v.Identifier == "" {
		v.Identifier = defaultIdentifier
	}
	if v.WireProfile == "" {
		v.WireProfile = defaultProfile
	}
	return v
}

// ValidateConfig validates the top-level BGP config (legacy fields). It does
// not validate the events sequence — that is Planner.Validate's job, since
// event ordering (state machine) and per-event faults are sequence-scoped.
func ValidateConfig(c *BGPConfig) error {
	if c == nil {
		return fmt.Errorf("bgp: config is required")
	}
	v := normalized(c)
	if v.Version != 4 {
		return fmt.Errorf("bgp: version %d unsupported; only version 4 is supported", v.Version)
	}
	if v.ASN > 65535 {
		return fmt.Errorf("bgp: my_as %d exceeds two-octet range", v.ASN)
	}
	// G-BGP-7：顶层 hold_time 同款（RFC 4271 §4.2：0 或 >= 3）。
	if v.HoldTime != 0 && v.HoldTime < 3 {
		return fmt.Errorf("bgp: hold_time %d invalid; RFC 4271 §4.2 allows 0 (disabled) or >= 3 seconds", v.HoldTime)
	}
	if ip := net.ParseIP(v.Identifier); ip == nil || ip.To4() == nil || ip.Equal(net.IPv4zero) {
		return fmt.Errorf("bgp: identifier %q must be a non-zero IPv4 address", v.Identifier)
	}
	if v.WireProfile != defaultProfile {
		return fmt.Errorf("bgp: profile %q unsupported", v.WireProfile)
	}
	if len(v.Capabilities) != 0 {
		return fmt.Errorf("bgp: capabilities are unsupported")
	}
	if len(v.Update) != 0 {
		return fmt.Errorf("bgp: UPDATE configuration is unsupported")
	}
	if len(v.Notification) != 0 {
		return fmt.Errorf("bgp: NOTIFICATION configuration is unsupported")
	}
	if len(v.Marker) != 0 && len(v.Marker) != 16 {
		return fmt.Errorf("bgp: marker must be 16 bytes")
	}
	for _, b := range v.Marker {
		if b != 0xff {
			return fmt.Errorf("bgp: marker must be all ones")
		}
	}
	if v.Length != 0 && (v.Length < bgpHeaderLen || v.Length > bgpMaxLen) {
		return fmt.Errorf("bgp: length %d outside 19..4096", v.Length)
	}
	return nil
}

// validateEventConfig validates a single event's internal consistency (the
// fields that do not depend on sequence position). Sequence/state constraints
// live in Planner.validateState.
func validateEventConfig(ev *core.BGPEvent) error {
	switch ev.Kind {
	case "open":
		if ev.Version != 0 && ev.Version != 4 {
			return fmt.Errorf("bgp: version %d unsupported; only version 4 is supported", ev.Version)
		}
		if ev.MyAS > 65535 {
			return fmt.Errorf("bgp: my_as %d exceeds two-octet range", ev.MyAS)
		}
		if ev.Identifier != "" {
			if ip := net.ParseIP(ev.Identifier); ip == nil || ip.To4() == nil || ip.Equal(net.IPv4zero) {
				return fmt.Errorf("bgp: identifier %q must be a non-zero IPv4 address", ev.Identifier)
			}
		}
		// G-BGP-7：RFC 4271 §4.2 规定 Hold Time 只能是 0 或不小于 3 秒
		// （1–2 秒是"立即过期"的无意义值）。0 = 不启用保持计时器，放行。
		if ev.HoldTime != 0 && ev.HoldTime < 3 {
			return fmt.Errorf("bgp: hold_time %d invalid; RFC 4271 §4.2 allows 0 (disabled) or >= 3 seconds", ev.HoldTime)
		}
	case "update":
		if err := validateUpdateEvent(ev); err != nil {
			return err
		}
	case "notification":
		// RFC 4271 §4.3: only defined error codes. We pin the stable
		// Hold Timer Expired (4/0) case; unknown codes are not injected.
		if ev.ErrorCode != 4 {
			return fmt.Errorf("bgp: notification error_code %d unsupported; only 4 (Hold Timer Expired)", ev.ErrorCode)
		}
		if ev.ErrorSubcode != 0 {
			return fmt.Errorf("bgp: notification error_subcode %d unsupported; only 0", ev.ErrorSubcode)
		}
	case "wire_fault":
		// Fault injection is a validation-boundary directive (design §7):
		// the planner/validator rejects the config here, so the fault never
		// becomes valid wire bytes. The error keyword matches the fault kind.
		switch ev.FaultKind {
		case "marker":
			return fmt.Errorf("bgp: marker must be all ones")
		case "length":
			length := uint16(bgpHeaderLen)
			if ev.Value != nil {
				length = *ev.Value
			}
			if length < bgpHeaderLen || length > bgpMaxLen {
				return fmt.Errorf("bgp: length %d outside 19..4096", length)
			}
			return fmt.Errorf("bgp: length fault injected")
		case "type":
			typ := byte(5)
			if ev.Value != nil {
				typ = byte(*ev.Value)
			}
			return fmt.Errorf("bgp: unknown message type %d", typ)
		default:
			return fmt.Errorf("bgp: wire fault kind %q unsupported", ev.FaultKind)
		}
	case "keepalive", "":
		// no payload; nothing to validate
	default:
		return fmt.Errorf("bgp: event kind %q unsupported", ev.Kind)
	}
	if ev.Direction != "c2s" && ev.Direction != "s2c" {
		return fmt.Errorf("bgp: direction %q must be c2s or s2c", ev.Direction)
	}
	return nil
}

// validateUpdateEvent checks the UPDATE-only fields (prefix/attribute address
// family and bounds). Bad CIDR/address-family returns a keyword containing
// "address" so the N9 case (IPv6 NLRI in IPv4 profile) is rejected distinctly.
func validateUpdateEvent(ev *core.BGPEvent) error {
	for _, p := range ev.WithdrawnPrefixes {
		if err := validateIPv4Prefix(p); err != nil {
			return err
		}
	}
	for _, p := range ev.NLRI {
		if err := validateIPv4Prefix(p); err != nil {
			return err
		}
	}
	if ev.Attributes != nil {
		if v := ev.Attributes.Origin; v != nil && *v > 2 {
			return fmt.Errorf("bgp: origin %d invalid; 0 IGP/1 EGP/2 INCOMPLETE", *v)
		}
		if ev.Attributes.NextHop != "" {
			if ip := net.ParseIP(ev.Attributes.NextHop); ip == nil || ip.To4() == nil {
				return fmt.Errorf("bgp: next_hop %q must be an IPv4 address", ev.Attributes.NextHop)
			}
		}
		for _, a := range ev.Attributes.ASPath {
			if a > 65535 {
				return fmt.Errorf("bgp: my_as %d exceeds two-octet range", a)
			}
		}
		for _, c := range ev.Attributes.Communities {
			if !validCommunity(c) {
				return fmt.Errorf("bgp: community %q invalid", c)
			}
		}
	}
	// §3.4/§7 #13：编码后总长超 4096 在**校验面**即拒。BuildUpdate 的权威
	// 检查只在生成期触发，而链路径生成期错误被 drive 吞成 "planner produced
	// 0 packet configs"（testcase #35 实测），锚词到不了 4096——校验面必须
	// 独立给出同一锚词（前缀合法性与属性编码已在上方判定，这里只量长度）。
	withdrawnLen := 0
	for _, p := range ev.WithdrawnPrefixes {
		_, addr := encodePrefix(p)
		withdrawnLen += 1 + len(addr)
	}
	nlriLen := 0
	for _, p := range ev.NLRI {
		_, addr := encodePrefix(p)
		nlriLen += 1 + len(addr)
	}
	attrsLen := 0
	if ev.Attributes != nil {
		attrs, err := encodeAttributes(ev.Attributes)
		if err != nil {
			return err
		}
		attrsLen = len(attrs)
	}
	if total := bgpHeaderLen + 4 + withdrawnLen + attrsLen + nlriLen; total > bgpMaxLen {
		return fmt.Errorf("bgp: message length %d exceeds 4096", total)
	}
	return nil
}

// validateIPv4Prefix parses a CIDR and rejects anything that is not a canonical
// IPv4 prefix. The address-family mismatch (IPv6) is surfaced as "address".
func validateIPv4Prefix(p string) error {
	if !strings.Contains(p, "/") {
		return fmt.Errorf("bgp: NLRI %q must be CIDR (prefix/len)", p)
	}
	ip, ipnet, err := net.ParseCIDR(p)
	if err != nil || ip.To4() == nil {
		return fmt.Errorf("bgp: address %q is not a valid IPv4 prefix", p)
	}
	ones, _ := ipnet.Mask.Size()
	if ones == 0 {
		return fmt.Errorf("bgp: prefix length 0 invalid")
	}
	return nil
}

func validCommunity(c string) bool {
	if c == "" {
		return false
	}
	switch c {
	case "NO_EXPORT", "NO_ADVERTISE", "NO_EXPORT_SUBCONFED":
		return true
	}
	// ASN:N2 format (plain numeric 4-octet community) — not required by the
	// design's fixed profile, but a plain parse is harmless.
	return false
}

func marker() []byte {
	m := make([]byte, 16)
	for i := range m {
		m[i] = 0xff
	}
	return m
}

// prelude writes the common 19-byte header (marker + length + type). The
// length field is left zero and patched by finalize, matching the s7/iec104
// pattern of computing the total after the body is assembled.
func prelude(bodyLen int, typ byte) []byte {
	b := make([]byte, bgpHeaderLen, bgpHeaderLen+bodyLen)
	copy(b[:16], marker())
	b[18] = typ
	return b
}

func finalize(b []byte) {
	binary.BigEndian.PutUint16(b[16:18], uint16(len(b)))
}

func BuildOpen(c *BGPConfig) ([]byte, error) {
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	if c.Events != nil || c.Sessions != nil {
		return nil, fmt.Errorf("bgp: BuildOpen does not accept events/sessions; use BuildEvent")
	}
	v := normalized(c)
	b := make([]byte, bgpHeaderLen+10)
	copy(b[:16], marker())
	b[18] = msgOpen
	b[19] = v.Version
	binary.BigEndian.PutUint16(b[20:22], uint16(v.ASN))
	binary.BigEndian.PutUint16(b[22:24], v.HoldTime)
	copy(b[24:28], net.ParseIP(v.Identifier).To4())
	b[28] = 0
	binary.BigEndian.PutUint16(b[16:18], uint16(len(b)))
	return b, nil
}

func BuildKeepalive() ([]byte, error) {
	b := make([]byte, bgpHeaderLen)
	copy(b[:16], marker())
	b[18] = msgKeepalive
	binary.BigEndian.PutUint16(b[16:18], bgpHeaderLen)
	return b, nil
}

// BuildEvent dispatches a single BGPEvent to its message builder. A wire_fault
// event returns the faulted header bytes (used by negative tests through the
// planner's failure path, not emitted as valid wire traffic).
func BuildEvent(ev core.BGPEvent) ([]byte, error) {
	if err := validateEventConfig(&ev); err != nil {
		return nil, err
	}
	switch ev.Kind {
	case "open":
		return buildOpenEvent(&ev)
	case "keepalive", "":
		return BuildKeepalive()
	case "update":
		return BuildUpdate(&ev)
	case "notification":
		return BuildNotification(&ev)
	case "wire_fault":
		return nil, fmt.Errorf("bgp: wire_fault event rejected at validation")
	}
	return nil, fmt.Errorf("bgp: event kind %q unsupported", ev.Kind)
}

// buildOpenEvent encodes an OPEN from one event, using the open's own
// version/my_as/hold_time/identifier (design §2: each open's fields belong to
// its sender).
func buildOpenEvent(ev *core.BGPEvent) ([]byte, error) {
	version := ev.Version
	if version == 0 {
		version = defaultVersion
	}
	if version != 4 {
		return nil, fmt.Errorf("bgp: version %d unsupported; only version 4 is supported", version)
	}
	asn := ev.MyAS
	if asn == 0 {
		asn = defaultASN
	}
	if asn > 65535 {
		return nil, fmt.Errorf("bgp: my_as %d exceeds two-octet range", asn)
	}
	ident := ev.Identifier
	if ident == "" {
		ident = defaultIdentifier
	}
	if ip := net.ParseIP(ident); ip == nil || ip.To4() == nil || ip.Equal(net.IPv4zero) {
		return nil, fmt.Errorf("bgp: identifier %q must be a non-zero IPv4 address", ident)
	}
	b := make([]byte, bgpHeaderLen+10)
	copy(b[:16], marker())
	b[18] = msgOpen
	b[19] = version
	binary.BigEndian.PutUint16(b[20:22], uint16(asn))
	binary.BigEndian.PutUint16(b[22:24], ev.HoldTime)
	copy(b[24:28], net.ParseIP(ident).To4())
	b[28] = 0
	binary.BigEndian.PutUint16(b[16:18], uint16(len(b)))
	return b, nil
}

// BuildUpdate encodes an UPDATE (RFC 4271 §4.3) from one event: withdrawn
// routes length + withdrawn prefixes, total path attribute length + path
// attributes, then NLRI. All lengths are patched to the actual encoded bytes.
func BuildUpdate(ev *core.BGPEvent) ([]byte, error) {
	var withdrawn []byte
	for _, p := range ev.WithdrawnPrefixes {
		plen, addr := encodePrefix(p)
		withdrawn = append(withdrawn, plen)
		withdrawn = append(withdrawn, addr...)
	}
	attrs, err := encodeAttributes(ev.Attributes)
	if err != nil {
		return nil, err
	}
	var nlri []byte
	for _, p := range ev.NLRI {
		plen, addr := encodePrefix(p)
		nlri = append(nlri, plen)
		nlri = append(nlri, addr...)
	}
	// §3.4/§7：withdrawn_len 与 path_attr_len 都是 2 字节字段；任一长度超过
	// 65535 会产生截断溢出，必须拒绝而非静默绕回。base 是 2 字节 withdrawn_len
	// 头 + 2 字节 path_attr_len 头。
	if len(withdrawn) > 0xffff || len(attrs) > 0xffff {
		return nil, fmt.Errorf("bgp: update body too large (withdrawn %d, attrs %d bytes)", len(withdrawn), len(attrs))
	}
	body := make([]byte, 0, 4+len(withdrawn)+len(attrs)+len(nlri))
	body = append(body, byte(len(withdrawn)>>8), byte(len(withdrawn)))
	body = append(body, withdrawn...)
	body = append(body, byte(len(attrs)>>8), byte(len(attrs)))
	body = append(body, attrs...)
	body = append(body, nlri...)
	// §3.1/§7：BGP 报文总长 19..4096；最终编码长度超过 4096 必须拒绝。
	total := bgpHeaderLen + len(body)
	if total > bgpMaxLen {
		return nil, fmt.Errorf("bgp: message length %d exceeds 4096", total)
	}
	b := prelude(len(body), msgUpdate)
	b = append(b, body...)
	finalize(b)
	return b, nil
}

// encodePrefix encodes an IPv4 CIDR as prefix-length + ceil(plen/8) address
// bytes (design §3.4). It is the validation-walked caller, so the prefix is
// known to be canonical IPv4.
func encodePrefix(cidr string) (byte, []byte) {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	ones, _ := ipnet.Mask.Size()
	nbytes := (ones + 7) / 8
	addr := ip.To4()
	return byte(ones), addr[:nbytes]
}

// encodeAttributes encodes the RFC 4271 path attributes (§3.4). Attributes
// absent (nil pointer / zero fields) are skipped so the withdraw case with
// `attributes:{}` produces path-attributes length 0. Each attribute is emitted
// only when its config field is present: Origin uses a pointer (IGP=0 is a
// real value), the rest use non-empty/zero thresholds.
func encodeAttributes(attrs *core.BGPUpdateAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, nil
	}
	var out []byte
	if attrs.Origin != nil {
		if *attrs.Origin > 2 {
			return nil, fmt.Errorf("bgp: origin %d invalid; 0 IGP/1 EGP/2 INCOMPLETE", *attrs.Origin)
		}
		var err error
		if out, err = appendPathAttr(out, flagTransitive, attrOrigin, []byte{*attrs.Origin}); err != nil {
			return nil, err
		}
	}
	if len(attrs.ASPath) > 0 {
		asBytes := make([]byte, 0, 2+len(attrs.ASPath)*2)
		asBytes = append(asBytes, asSequence, byte(len(attrs.ASPath)))
		for _, a := range attrs.ASPath {
			if a > 65535 {
				return nil, fmt.Errorf("bgp: my_as %d exceeds two-octet range", a)
			}
			asBytes = append(asBytes, byte(a>>8), byte(a))
		}
		var err error
		if out, err = appendPathAttr(out, flagTransitive, attrASPath, asBytes); err != nil {
			return nil, err
		}
	}
	if attrs.NextHop != "" {
		ip := net.ParseIP(attrs.NextHop)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("bgp: next_hop %q must be an IPv4 address", attrs.NextHop)
		}
		var err error
		if out, err = appendPathAttr(out, flagTransitive, attrNextHop, ip.To4()); err != nil {
			return nil, err
		}
	}
	if attrs.MultiExitDisc != 0 {
		var err error
		if out, err = appendPathAttr(out, flagOptional, attrMultiExit, uint32Bytes(attrs.MultiExitDisc)); err != nil {
			return nil, err
		}
	}
	if attrs.LocalPref != 0 {
		var err error
		if out, err = appendPathAttr(out, flagTransitive, attrLocalPref, uint32Bytes(attrs.LocalPref)); err != nil {
			return nil, err
		}
	}
	if len(attrs.Communities) > 0 {
		var cb []byte
		for _, c := range attrs.Communities {
			code, err := communityValue(c)
			if err != nil {
				return nil, err
			}
			cb = append(cb, uint32Bytes(code)...)
		}
		var err error
		if out, err = appendPathAttr(out, flagOptionalTrans, attrCommunities, cb); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// appendPathAttr writes flags | type code | 1-octet length | value. All
// attributes in the design's fixed profile are < 256 bytes, so the one-octet
// length form is always used; an attribute whose value length is >= 256 must
// use extended-length encoding (§3.4), which is out of scope, so it is
// rejected here rather than silently truncating byte(len(val)).
func appendPathAttr(out []byte, flags byte, typ byte, val []byte) ([]byte, error) {
	if len(val) >= 256 {
		return out, fmt.Errorf("bgp: attribute type %d length %d exceeds one-octet range; extended-length is unsupported", typ, len(val))
	}
	out = append(out, flags, typ, byte(len(val)))
	out = append(out, val...)
	return out, nil
}

func uint32Bytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func communityValue(c string) (uint32, error) {
	switch c {
	case "NO_EXPORT":
		return communityWellKnown, nil // 0xffffff01
	case "NO_ADVERTISE":
		return 0xffffff02, nil
	case "NO_EXPORT_SUBCONFED":
		return 0xffffff03, nil
	}
	return 0, fmt.Errorf("bgp: community %q invalid", c)
}

// BuildNotification encodes a NOTIFICATION (RFC 4271 §4.4) from one event:
// error code + error subcode + optional data. The Hold Timer Expired case
// (4/0, empty data) is 21 bytes.
func BuildNotification(ev *core.BGPEvent) ([]byte, error) {
	if ev.ErrorCode != 4 {
		return nil, fmt.Errorf("bgp: notification error_code %d unsupported; only 4 (Hold Timer Expired)", ev.ErrorCode)
	}
	if ev.ErrorSubcode != 0 {
		return nil, fmt.Errorf("bgp: notification error_subcode %d unsupported; only 0", ev.ErrorSubcode)
	}
	b := prelude(2, msgNotification)
	b = append(b, ev.ErrorCode, ev.ErrorSubcode)
	finalize(b)
	return b, nil
}
