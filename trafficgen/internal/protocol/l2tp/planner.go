// Package l2tp implements the L2TP (Layer 2 Tunneling Protocol, 二层隧道协议)
// planner for UDP port 1701. It supports both L2TPv2 (RFC 2661) and L2TPv3
// (RFC 3931) data + control planes, plus PPP (Point-to-Point Protocol, 点对点
// 协议, RFC 1661) frame encapsulation.
//
// The L2TP control plane uses AVP (Attribute-Value Pair, 属性值对) sequences
// per RFC 2661 §4.1. The AVP header is 6 bytes (M|H|rsvd|Length(10 bits) +
// Vendor ID(2) + Attribute Type(2)); the 10-bit Length field counts the whole
// AVP including the 6-byte header (min 6, max 1023). There is NO inter-AVP
// padding — RFC 2661 §4.1 and RFC 3931 §5.1 define no alignment requirement,
// and Wireshark's packet-l2tp.c advances by the declared Length only.
// The planner writes 14
// control-message types (SCCRQ/SCCRP/SCCCN/StopCCN/HELLO/OCRQ/OCRP/OCCN/
// ICRQ/ICRP/ICCN/CDN/WEN/SLI) and dispatches scenarios based on the
// L2TPConfig.Role ("lac" or "lns") field. Data messages follow RFC 2661
// §3.1 (v2) or RFC 3931 §3.1 (v3, no Tunnel ID + optional Cookie).
//
// The L2TPv3 vs L2TPv2 distinction is critical: L2TPv2 Session ID is 16 bits;
// L2TPv3 Session ID is 32 bits and v3 data messages carry NO Tunnel ID. The
// planner switches header layout based on cfg.Version.
package l2tp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Default ports per RFC 2661 §3.
const (
	DefaultPort uint16 = 1701 // L2TP control + data unified UDP port

	DefaultTTL uint8 = 64

	// Version numbers as they appear on the wire (RFC 2661/3931).
	VersionL2TPv2 uint8 = 2
	VersionL2TPv3 uint8 = 3

	// Maximum AVP length per RFC 2661 §4.1 (10-bit Length field, including
	// the 6-byte header). The planner previously used 0x0FFF (12 bits), which
	// let AVPs exceed 1023 and corrupted reserved bits 10-11 of the first
	// word.
	maxAVPLength uint16 = 0x03FF // 1023

	// Control-message header sizes (v2 vs v3).
	v2ControlHeaderSize = 12 // Flags+Ver(2) + Length(2) + TunnelID(2) + SessionID(2) + Ns(2) + Nr(2)
	v3ControlHeaderSize = 14 // v2 + extra 2 bytes for 32-bit Session ID

	// Data-message header sizes.
	v2DataHeaderSize   = 6 // TunID(2) + SesID(2) minimum; +Length/Ns/Nr/Offset when set
	v3DataHeaderSize   = 6 // Flags(1) + Ver(1) + SesID(4)
)

// Flag bits for L2TPv2 control messages (RFC 2661 §3.1, 16-bit big-endian).
const (
	flagT2 uint16 = 0x8000 // Type: 1 = control
	flagL2 uint16 = 0x4000 // Length present
	flagS2 uint16 = 0x0800 // Sequence numbers present
	flagO2 uint16 = 0x0200 // Offset present
	flagP2 uint16 = 0x0100 // Priority
	// Low 4 bits = Ver (2 = v2, 3 = v3).
)

// L2TPv3 data message flags (RFC 3931 §3.1, 8-bit). Cookie Size in bits 5-4.
const (
	v3FlagCookieSize4  byte = 0x20 // 4-byte cookie
	v3FlagCookieSize8  byte = 0x40 // 8-byte cookie
	v3FlagCookieSize16 byte = 0x60 // 16-byte cookie
)

// AVP attribute types (RFC 2661 §5 / RFC 4045). Only the IETF/standard ones
// the planner auto-generates from L2TPConfig fields.
const (
	attrMessageType        uint16 = 0
	attrResultCode         uint16 = 1
	attrProtocolVersion    uint16 = 2
	attrFramingCaps        uint16 = 3
	attrBearerCaps         uint16 = 4
	attrTieBreaker         uint16 = 5
	attrFirmwareRev        uint16 = 6
	attrHostName           uint16 = 7
	attrVendorName         uint16 = 8
	attrAssignedTunnelID   uint16 = 9
	attrReceiveWindowSize  uint16 = 10
	attrChallenge          uint16 = 11
	attrQ931CauseCode      uint16 = 12
	attrChallengeResponse  uint16 = 13
	attrAssignedSessionID  uint16 = 14
	attrCallSerialNumber   uint16 = 15
	attrMinimumBPS         uint16 = 16
	attrMaximumBPS         uint16 = 17
	attrBearerType         uint16 = 18
	attrFramingType        uint16 = 19
	attrCalledNumber       uint16 = 20
	attrCallingNumber      uint16 = 21
	attrACCM               uint16 = 36
)

// Message Type AVP values (RFC 2661 §5).
const (
	msgSCCRQ  uint16 = 1
	msgSCCRP  uint16 = 2
	msgSCCCN  uint16 = 3
	msgStopCCN uint16 = 4
	msgHELLO  uint16 = 5
	msgOCRQ   uint16 = 6
	msgOCRP   uint16 = 7
	msgOCCN   uint16 = 8
	msgICRQ   uint16 = 9
	msgICRP   uint16 = 10
	msgICCN   uint16 = 11
	msgCDN    uint16 = 12
	msgWEN    uint16 = 14
	msgSLI    uint16 = 15
)

// Scenario type strings (L2TPStep.Type).
const (
	stepSCCRQ  = "sccrq"
	stepSCCRP  = "sccrp"
	stepSCCCN  = "scccn"
	stepStopCCN = "stopccn"
	stepHELLO  = "hello"
	stepOCRQ   = "ocrq"
	stepOCRP   = "ocrp"
	stepOCCN   = "occn"
	stepICRQ   = "icrq"
	stepICRP   = "icrp"
	stepICCN   = "iccn"
	stepCDN    = "cdn"
	stepWEN    = "wen"
	stepSLI    = "sli"
)

// Planner emits L2TP packet configs on a UDP/1701 4-tuple.
type Planner struct{}

// NewPlanner returns a new L2TP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "l2tp" }

// Validate validates an L2TP flow spec (read-only per validate_conventions.md
// §1.1: never mutate spec, never fill defaults -- Plan handles defaults).
func (p *Planner) Validate(spec core.FlowSpec) error {
	// IP validation: empty = use default (filled by Plan).
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("l2tp: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("l2tp: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}
	// IP-version match.
	if spec.SrcIP != "" && spec.DstIP != "" {
		src := net.ParseIP(spec.SrcIP)
		dst := net.ParseIP(spec.DstIP)
		if src != nil && dst != nil {
			srcV4 := src.To4() != nil
			dstV4 := dst.To4() != nil
			if srcV4 != dstV4 {
				return fmt.Errorf("l2tp: SrcIP %s and DstIP %s must be same IP version", spec.SrcIP, spec.DstIP)
			}
		}
	}

	// Port validation.
	if spec.SrcPort > 65535 {
		return fmt.Errorf("l2tp: SrcPort %d out of range [0, 65535]", spec.SrcPort)
	}
	if spec.DstPort > 65535 {
		return fmt.Errorf("l2tp: DstPort %d out of range [0, 65535]", spec.DstPort)
	}

	// L2TPConfig must be present.
	if spec.L2TP == nil {
		return fmt.Errorf("l2tp: L2TP config is required")
	}
	cfg := spec.L2TP

	// Version validation: only 2 or 3 allowed.
	switch cfg.Version {
	case 0, VersionL2TPv2:
		// ok (0 defaults to v2 in Plan)
	case VersionL2TPv3:
		// ok
	default:
		return fmt.Errorf("l2tp: Version %d not in supported list (allowed: 2=v2, 3=v3)", cfg.Version)
	}

	// Role validation.
	switch cfg.Role {
	case "", "lac", "lns":
		// ok
	default:
		return fmt.Errorf("l2tp: Role %q not in supported list (allowed: lac, lns)", cfg.Role)
	}

	// HelloInterval sanity check.
	if cfg.HelloInterval < 0 {
		return fmt.Errorf("l2tp: HelloInterval %d must be >= 0", cfg.HelloInterval)
	}

	// Cookie length (L2TPv3) must be 0/4/8/16 if Version is 3.
	if cfg.Version == VersionL2TPv3 {
		switch len(cfg.Cookie) {
		case 0, 4, 8, 16:
			// ok
		default:
			return fmt.Errorf("l2tp: Cookie length %d invalid (allowed: 0, 4, 8, 16; RFC 3931 §3.1)", len(cfg.Cookie))
		}
	}

	// Validate CustomAVPs and per-step AVPs for AVP length.
	for i, a := range cfg.CustomAVPs {
		if err := validateAVPLength(i, a); err != nil {
			return err
		}
	}
	for si, st := range cfg.Scenarios {
		for ai, a := range st.AVPs {
			if err := validateAVPLengthForStep(si, st.Type, ai, a); err != nil {
				return err
			}
		}
		if !isKnownStepType(st.Type) {
			return fmt.Errorf("l2tp: Scenarios[%d].Type %q not in supported list", si, st.Type)
		}
	}

	// Validate PPPFrames Protocol field (must be a real PPP protocol).
	for i, f := range cfg.PPPFrames {
		if f.Protocol == 0 {
			return fmt.Errorf("l2tp: PPPFrames[%d].Protocol 0 invalid (must be a PPP protocol value, e.g. 0x0021=IPv4)", i)
		}
	}

	return nil
}

// validateAVPLength checks that an AVP value fits within the 10-bit Length
// field (max 1023 bytes total AVP size including 6-byte header) per RFC 2661
// §4.1.
func validateAVPLength(i int, a core.L2TPAVP) error {
	total := 6 + len(a.Value)
	if total > int(maxAVPLength) {
		return fmt.Errorf("l2tp: CustomAVPs[%d] total length %d exceeds max %d (RFC 2661 §4.1, 10-bit Length field)", i, total, maxAVPLength)
	}
	return nil
}

// validateAVPLengthForStep is validateAVPLength for a per-step AVP.
func validateAVPLengthForStep(si int, stepType string, ai int, a core.L2TPAVP) error {
	total := 6 + len(a.Value)
	if total > int(maxAVPLength) {
		return fmt.Errorf("l2tp: Scenarios[%d] (%s) AVPs[%d] total length %d exceeds max %d (RFC 2661 §4.1, 10-bit Length field)", si, stepType, ai, total, maxAVPLength)
	}
	return nil
}

// isKnownStepType reports whether s is a known L2TP control message type.
func isKnownStepType(s string) bool {
	switch s {
	case stepSCCRQ, stepSCCRP, stepSCCCN, stepStopCCN, stepHELLO,
		stepOCRQ, stepOCRP, stepOCCN,
		stepICRQ, stepICRP, stepICCN,
		stepCDN, stepWEN, stepSLI:
		return true
	}
	return false
}

// messageTypeForStep maps a step type string to its Message Type AVP value.
func messageTypeForStep(s string) uint16 {
	switch s {
	case stepSCCRQ:
		return msgSCCRQ
	case stepSCCRP:
		return msgSCCRP
	case stepSCCCN:
		return msgSCCCN
	case stepStopCCN:
		return msgStopCCN
	case stepHELLO:
		return msgHELLO
	case stepOCRQ:
		return msgOCRQ
	case stepOCRP:
		return msgOCRP
	case stepOCCN:
		return msgOCCN
	case stepICRQ:
		return msgICRQ
	case stepICRP:
		return msgICRP
	case stepICCN:
		return msgICCN
	case stepCDN:
		return msgCDN
	case stepWEN:
		return msgWEN
	case stepSLI:
		return msgSLI
	}
	return 0
}

// isLACOriginatedStep returns true when the step is naturally emitted by the
// LAC side (initiator). For LNS-originated steps (sccrp, ocrp, icrp), the
// direction is flipped when Role="lac" (they become "down" / incoming).
//
// Per RFC 2661 §7: LAC sends SCCRQ/SCCCN/OCRQ/OCCN/ICRQ/ICCN; LNS replies
// with SCCRP/OCRP/ICRP. CDN/HELLO/StopCCN/WEN/SLI are tunnel-level and can
// originate from either side -- we treat them as LAC-originated by default
// (the initiator side).
func isLACOriginatedStep(s string) bool {
	switch s {
	case stepSCCRQ, stepSCCCN, stepOCRQ, stepOCCN,
		stepICRQ, stepICCN, stepCDN, stepHELLO, stepStopCCN, stepWEN, stepSLI:
		return true
	}
	// sccrp, ocrp, icrp: LNS-originated replies.
	return false
}

// isTunnelLevelStep reports whether the step is a tunnel-level control
// message (no session association). Per RFC 2661 §5.1, the Session ID in
// the L2TP header for tunnel-level messages MUST be 0.
func isTunnelLevelStep(s string) bool {
	switch s {
	case stepSCCRQ, stepSCCRP, stepSCCCN, stepStopCCN, stepHELLO:
		return true
	}
	return false
}

// Plan emits L2TP packet configs (control + data) on the configured 4-tuple.
// It always emits to UDP/1701 unless spec.SrcPort / spec.DstPort override.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		now := time.Now()
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		ipidCounter := uint32(0)
		nextIPID := func() uint16 {
			ipidCounter++
			return uint16(ipidCounter)
		}

		cfg := spec.L2TP
		version := cfg.Version
		if version == 0 {
			version = VersionL2TPv2
		}

		// Resolve effective SrcPort/DstPort (default 1701).
		effectiveSrcPort := spec.SrcPort
		if effectiveSrcPort == 0 {
			effectiveSrcPort = DefaultPort
		}
		effectiveDstPort := spec.DstPort
		if effectiveDstPort == 0 {
			effectiveDstPort = DefaultPort
		}

		// Resolve Role (default lac).
		role := cfg.Role
		if role == "" {
			role = "lac"
		}

		// Resolve identifiers. Per RFC 2661, the Session ID = 0 is a valid
		// value (especially for tunnel-level messages); we do NOT default
		// Session ID 0 -> 1. LocalTunnelID defaults to 1 when 0 (RFC 2661
		// §5.2: tunnel ID 0 = unassigned, so the planner picks a default).
		localTunID := cfg.LocalTunnelID
		if localTunID == 0 {
			localTunID = 1
		}
		peerTunID := cfg.PeerTunnelID
		localSesID := cfg.LocalSessionID
		peerSesID := cfg.PeerSessionID
		// 32-bit v3 Session IDs fall back to the 16-bit value when unset.
		localSesID32 := cfg.LocalSessionID32
		if localSesID32 == 0 {
			localSesID32 = uint32(localSesID)
		}
		peerSesID32 := cfg.PeerSessionID32
		if peerSesID32 == 0 {
			peerSesID32 = uint32(peerSesID)
		}

		// State: dual Ns counters (LAC and LNS have independent send
		// sequence counters per RFC 2661 §5.8). localNs tracks the local
		// role's Ns; peerNs tracks the peer's Ns. Each starts at InitialNs
		// for the local side; peerNs always starts at 0.
		localNs := cfg.InitialNs
		peerNs := uint16(0)

		// Shared packet-emit closure that increments PacketIndex.
		packetIndex := uint64(0)
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) bool {
			cfgOut := core.PacketConfig{
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
			case configChan <- cfgOut:
				packetIndex++
				return true
			case <-ctx.Done():
				return false
			}
		}

		// emitStep builds and emits a single control message (L2TPv2 or
		// L2TPv3) using the configured L2TP identifiers. It uses the
		// correct Ns counter (localNs vs peerNs) based on the resolved
		// direction: "up" uses localNs, "down" uses peerNs. Nr is set to
		// the OTHER counter's value (= next expected Ns from the peer).
		emitStep := func(step core.L2TPStep, direction string) bool {
			// Determine AVP set for this step.
			avps := autoAVPsForStep(cfg, step.Type, localTunID, localSesID)
			// Append step-specific AVPs from the user.
			avps = append(avps, step.AVPs...)

			// Resolve effective Tunnel ID for this step.
			tunID := localTunID
			if step.TunnelIDOverride != nil {
				tunID = *step.TunnelIDOverride
			}

			// Resolve effective Session ID for this step.
			// Per RFC 2661 §5.1, tunnel-level messages have SesID=0 in
			// the header regardless of localSesID.
			sesID := localSesID
			sesID32 := localSesID32
			if isTunnelLevelStep(step.Type) {
				sesID = 0
				sesID32 = 0
			}
			if step.SessionIDOverride != nil {
				sesID = *step.SessionIDOverride
				sesID32 = uint32(*step.SessionIDOverride)
			}
			// For OCRP / ICRP replies, the SesID carries the peer's ID.
			if step.Type == stepOCRP || step.Type == stepICRP {
				if peerSesID != 0 {
					sesID = peerSesID
				}
				if peerSesID32 != 0 {
					sesID32 = peerSesID32
				}
			}

			// Pick Ns based on direction: "up" is from local side (localNs),
			// "down" is from peer (peerNs). Nr = other counter (next
			// expected Ns from the peer).
			var ns, nr uint16
			if direction == "up" {
				ns = localNs
				nr = peerNs
			} else {
				ns = peerNs
				nr = localNs
			}

			payload, err := buildControlMessage(version, tunID, sesID, sesID32, ns, nr, messageTypeForStep(step.Type), avps)
			if err != nil {
				return false
			}
			_ = peerTunID // reserved for future AVP echo handling

			// MAC and 4-tuple swap based on direction.
			var srcMAC, dstMAC, srcIP, dstIP string
			var srcPort, dstPort uint16
			if direction == "up" {
				srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
				srcIP, dstIP = spec.SrcIP, spec.DstIP
				srcPort, dstPort = effectiveSrcPort, effectiveDstPort
			} else {
				srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
				srcIP, dstIP = spec.DstIP, spec.SrcIP
				srcPort, dstPort = effectiveDstPort, effectiveSrcPort
			}

			if !emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, payload) {
				return false
			}

			// Increment the counter we used for Ns.
			if direction == "up" {
				localNs++
			} else {
				peerNs++
			}
			return true
		}

		// Resolve default MACs.
		upMAC, downMAC := spec.SrcMAC, spec.DstMAC
		if spec.SrcMAC == "" {
			upMAC = "aa:bb:cc:dd:ee:01"
		}
		if spec.DstMAC == "" {
			downMAC = "aa:bb:cc:dd:ee:02"
		}

		// Compute hello interval.
		helloInterval := time.Duration(cfg.HelloInterval) * time.Second
		if cfg.HelloInterval == 0 {
			helloInterval = 60 * time.Second
		}

		// ----- Walk Scenarios (control messages) -----
		for _, step := range cfg.Scenarios {
			if err := ctx.Err(); err != nil {
				return
			}

			direction := step.Direction
			if direction == "" {
				// Auto-resolve based on role + step type.
				if role == "lac" {
					if isLACOriginatedStep(step.Type) {
						direction = "up"
					} else {
						direction = "down"
					}
				} else { // lns
					if isLACOriginatedStep(step.Type) {
						direction = "down"
					} else {
						direction = "up"
					}
				}
			}

			// Wait before HELLO if not the first packet.
			if step.Type == stepHELLO && localNs != cfg.InitialNs && peerNs != 0 {
				select {
				case <-time.After(helloInterval):
				case <-ctx.Done():
					return
				}
			}

			if !emitStep(step, direction) {
				return
			}
		}

		// ----- Walk PPPFrames (data messages) -----
		for _, ppp := range cfg.PPPFrames {
			if err := ctx.Err(); err != nil {
				return
			}
			dir := ppp.Direction
			if dir == "" {
				dir = "up"
			}
			direction := dir
			if role == "lns" {
				direction = "down"
				if dir == "down" {
					direction = "up"
				}
			}

			var srcMAC, dstMAC, srcIP, dstIP string
			var srcPort, dstPort uint16
			if direction == "up" {
				srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
				if srcMAC == "" {
					srcMAC = upMAC
				}
				if dstMAC == "" {
					dstMAC = downMAC
				}
				srcIP, dstIP = spec.SrcIP, spec.DstIP
				srcPort, dstPort = effectiveSrcPort, effectiveDstPort
			} else {
				srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
				if srcMAC == "" {
					srcMAC = downMAC
				}
				if dstMAC == "" {
					dstMAC = upMAC
				}
				srcIP, dstIP = spec.DstIP, spec.SrcIP
				srcPort, dstPort = effectiveDstPort, effectiveSrcPort
			}

			// PPP frame: HDLC address+control flag (optional, RFC 1661 §6)
			// + 2-byte Protocol + Information bytes. Per RFC 1661 the HDLC
			// framing precedes the Protocol field.
			var pppBytes []byte
			if ppp.L2PPPHeader {
				pppBytes = make([]byte, 0, 2+2+len(ppp.Data))
				pppBytes = append(pppBytes, 0xFF, 0x03)
				pppBytes = append(pppBytes, u16BE(ppp.Protocol)...)
				pppBytes = append(pppBytes, ppp.Data...)
			} else {
				pppBytes = make([]byte, 0, 2+len(ppp.Data))
				pppBytes = append(pppBytes, u16BE(ppp.Protocol)...)
				pppBytes = append(pppBytes, ppp.Data...)
			}

			payload := buildDataMessage(version, localTunID, localSesID, localSesID32, cfg.Cookie, pppBytes)

			if !emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, payload) {
				return
			}
		}
	}()

	return configChan, nil
}

// autoAVPsForStep builds the default AVP set for a control message based on
// the L2TPConfig fields. The Message Type AVP (type 0) is always included
// first; auto-AVPs are merged with the step's user-supplied AVPs by the
// caller.
//
// The returned slice does NOT include the Message Type AVP -- buildControlMessage
// always prepends that AVP itself to guarantee it appears first per RFC 2661 §5.
func autoAVPsForStep(cfg *core.L2TPConfig, stepType string, localTunID, localSesID uint16) []core.L2TPAVP {
	var avps []core.L2TPAVP

	hostName := cfg.HostName
	if hostName == "" {
		hostName = "trafficgen"
	}
	vendorName := cfg.VendorName
	if vendorName == "" {
		vendorName = "trafficgen L2TP simulator"
	}
	tieBreaker := cfg.TieBreaker
	if tieBreaker == 0 {
		tieBreaker = 1
	}
	protoVer := cfg.ProtocolVersion
	if protoVer == 0 {
		protoVer = 0x0101
	}
	recvWin := cfg.ReceiveWindowSize
	if recvWin == 0 {
		recvWin = 4
	}

	switch stepType {
	case stepSCCRQ:
		// SCCRQ carries Protocol Version, Framing/Bearer Caps, Host Name,
		// Vendor Name, Assigned Tunnel ID, Receive Window Size, Tie Breaker.
		avps = append(avps,
			core.L2TPAVP{AttrType: attrProtocolVersion, Value: u16BE(protoVer)},
			core.L2TPAVP{AttrType: attrFramingCaps, Value: u32BE(cfg.FramingCaps)},
			core.L2TPAVP{AttrType: attrBearerCaps, Value: u32BE(cfg.BearerCaps)},
			core.L2TPAVP{AttrType: attrHostName, Value: append([]byte(hostName), 0)},
			core.L2TPAVP{AttrType: attrVendorName, Value: append([]byte(vendorName), 0)},
			core.L2TPAVP{AttrType: attrAssignedTunnelID, Value: u16BE(localTunID)},
			core.L2TPAVP{AttrType: attrReceiveWindowSize, Value: u16BE(recvWin)},
			core.L2TPAVP{AttrType: attrTieBreaker, Value: u64BE(tieBreaker)},
		)
		if cfg.FirmwareRev != 0 {
			avps = append(avps, core.L2TPAVP{AttrType: attrFirmwareRev, Value: u16BE(cfg.FirmwareRev)})
		}
	case stepSCCRP:
		// SCCRP same as SCCRQ (LNS side).
		avps = append(avps,
			core.L2TPAVP{AttrType: attrProtocolVersion, Value: u16BE(protoVer)},
			core.L2TPAVP{AttrType: attrFramingCaps, Value: u32BE(cfg.FramingCaps)},
			core.L2TPAVP{AttrType: attrBearerCaps, Value: u32BE(cfg.BearerCaps)},
			core.L2TPAVP{AttrType: attrHostName, Value: append([]byte(hostName), 0)},
			core.L2TPAVP{AttrType: attrVendorName, Value: append([]byte(vendorName), 0)},
			core.L2TPAVP{AttrType: attrAssignedTunnelID, Value: u16BE(localTunID)},
			core.L2TPAVP{AttrType: attrReceiveWindowSize, Value: u16BE(recvWin)},
			core.L2TPAVP{AttrType: attrTieBreaker, Value: u64BE(tieBreaker)},
		)
	case stepSCCCN:
		// SCCCN: just confirms the tunnel ID assigned by LNS.
		avps = append(avps,
			core.L2TPAVP{AttrType: attrAssignedTunnelID, Value: u16BE(localTunID)},
		)
	case stepOCRQ, stepICRQ:
		// Outgoing/Incoming Call Request: Assigned Session ID + Call Serial
		// + Called/Calling Number (if provided).
		avps = append(avps,
			core.L2TPAVP{AttrType: attrAssignedSessionID, Value: u16BE(localSesID)},
			core.L2TPAVP{AttrType: attrCallSerialNumber, Value: u32BE(1)},
		)
	case stepOCRP, stepICRP:
		// Reply: just confirms Session ID.
		avps = append(avps,
			core.L2TPAVP{AttrType: attrAssignedSessionID, Value: u16BE(localSesID)},
		)
	case stepOCCN, stepICCN:
		// Connect: TX Connect Speed (optional).
		avps = append(avps,
			core.L2TPAVP{AttrType: attrAssignedSessionID, Value: u16BE(localSesID)},
		)
	case stepStopCCN:
		// StopCCN: Assigned Tunnel ID + Result Code.
		rc := cfg.ResultCode
		if rc == 0 {
			rc = 1
		}
		ec := cfg.ErrorCode
		em := cfg.ErrorMessage
		if em == "" {
			em = "user request"
		}
		avps = append(avps,
			core.L2TPAVP{AttrType: attrAssignedTunnelID, Value: u16BE(localTunID)},
			core.L2TPAVP{AttrType: attrResultCode, Value: buildResultCodeValue(rc, ec, em)},
		)
	case stepCDN:
		// Call Disconnect Notify: Assigned Session ID + Result Code.
		rc := cfg.ResultCode
		if rc == 0 {
			rc = 1
		}
		ec := cfg.ErrorCode
		em := cfg.ErrorMessage
		if em == "" {
			em = "user request"
		}
		avps = append(avps,
			core.L2TPAVP{AttrType: attrAssignedSessionID, Value: u16BE(localSesID)},
			core.L2TPAVP{AttrType: attrResultCode, Value: buildResultCodeValue(rc, ec, em)},
		)
	case stepHELLO:
		// HELLO: just Message Type AVP (added by buildControlMessage).
	case stepWEN, stepSLI:
		// WEN / SLI: optional AVPs only; nothing auto-emitted.
	}

	// Append any custom AVPs from the config.
	avps = append(avps, cfg.CustomAVPs...)

	return avps
}

// buildResultCodeValue encodes (ResultCode, ErrorCode, ErrorMessage) per
// RFC 2661 §5.4: 2-byte Result Code + 2-byte Error Code + null-terminated
// UTF-8 message.
func buildResultCodeValue(rc, ec uint16, msg string) []byte {
	buf := make([]byte, 4+len(msg)+1)
	binary.BigEndian.PutUint16(buf[0:2], rc)
	binary.BigEndian.PutUint16(buf[2:4], ec)
	copy(buf[4:], msg)
	buf[4+len(msg)] = 0
	return buf
}

// buildControlMessage builds a complete L2TP control message (T=1, L=1, S=1)
// per RFC 2661 §3.1 (v2) or RFC 3931 §3.2 (v3, Session ID = 32 bits).
//
// The Message Type AVP (type 0) is always prepended as the first AVP per
// RFC 2661 §5.1. The AVP set is then appended (the caller has merged
// auto-generated + per-step AVPs). Returns the payload bytes.
func buildControlMessage(version uint8, tunID, sesID16 uint16, sesID32 uint32, ns, nr uint16, msgType uint16, avps []core.L2TPAVP) ([]byte, error) {
	// Prepend Message Type AVP.
	msgAVP := core.L2TPAVP{Mandatory: true, AttrType: attrMessageType, Value: u16BE(msgType)}
	allAVPs := append([]core.L2TPAVP{msgAVP}, avps...)

	// Build AVP bytes.
	avpBytes, err := buildAVPs(allAVPs)
	if err != nil {
		return nil, err
	}

	var headerSize int
	switch version {
	case VersionL2TPv2, 0:
		headerSize = v2ControlHeaderSize
	case VersionL2TPv3:
		headerSize = v3ControlHeaderSize
	default:
		return nil, fmt.Errorf("l2tp: unsupported version %d", version)
	}

	totalLen := headerSize + len(avpBytes)
	payload := make([]byte, totalLen)

	// Flags + Ver (2 bytes).
	var flags uint16 = flagT2 | flagL2 | flagS2
	if version == VersionL2TPv3 {
		flags |= uint16(VersionL2TPv3)
	} else {
		flags |= uint16(VersionL2TPv2)
	}
	binary.BigEndian.PutUint16(payload[0:2], flags)
	// Length (2 bytes).
	binary.BigEndian.PutUint16(payload[2:4], uint16(totalLen))
	// Tunnel ID (2 bytes).
	binary.BigEndian.PutUint16(payload[4:6], tunID)
	// Session ID: 2 bytes for v2, 4 bytes for v3.
	if version == VersionL2TPv3 {
		binary.BigEndian.PutUint32(payload[6:10], sesID32)
		// Ns / Nr at offset 10/12.
		binary.BigEndian.PutUint16(payload[10:12], ns)
		binary.BigEndian.PutUint16(payload[12:14], nr)
		copy(payload[14:], avpBytes)
	} else {
		binary.BigEndian.PutUint16(payload[6:8], sesID16)
		binary.BigEndian.PutUint16(payload[8:10], ns)
		binary.BigEndian.PutUint16(payload[10:12], nr)
		copy(payload[12:], avpBytes)
	}

	return payload, nil
}

// buildDataMessage builds an L2TP data message (T=0).
//
// For v2 (RFC 2661 §3.1): TunID + SesID + PPP payload, no Length/Ns/Nr/Offset.
// For v3 (RFC 3931 §3.1): Flags (1) + Ver (1) + SessionID (4) + optional
// Cookie (0/4/8/16 bytes, per cfg.Cookie length) + L2 payload.
//
// The v3 Flags byte encodes the Cookie size in bits 5-4 (0x00=no cookie,
// 0x20=4 bytes, 0x40=8 bytes, 0x60=16 bytes). The Cookie field, when
// present, is written immediately after the Session ID per RFC 3931 §3.1.
func buildDataMessage(version uint8, localTunID uint16, localSesID uint16, localSesID32 uint32, cookie []byte, pppPayload []byte) []byte {
	if version == VersionL2TPv3 {
		// v3 data header: 6 bytes (Flags + Ver + 32-bit Session ID).
		hdr := make([]byte, 6)
		// v3 flags byte: bits 5-4 = Cookie Size (0/4/8/16 -> 0/1/2/3),
		// low 4 bits = 0, high 4 bits reserved. Ver=3 in low byte (byte 1 = 0x03).
		switch len(cookie) {
		case 4:
			hdr[0] = v3FlagCookieSize4
		case 8:
			hdr[0] = v3FlagCookieSize8
		case 16:
			hdr[0] = v3FlagCookieSize16
		default:
			// 0 (no cookie) or any unexpected length -> no cookie bits.
			hdr[0] = 0
		}
		hdr[1] = VersionL2TPv3
		binary.BigEndian.PutUint32(hdr[2:6], localSesID32)
		// Per RFC 3931 §3.1, the Cookie field follows the Session ID when
		// the Cookie Size flags are non-zero. Validation upstream ensures
		// len(cookie) is one of 0/4/8/16.
		out := make([]byte, 0, 6+len(cookie)+len(pppPayload))
		out = append(out, hdr...)
		out = append(out, cookie...)
		out = append(out, pppPayload...)
		return out
	}

	// v2 data message: TunID (2) + SesID (2) + PPP payload.
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], localTunID)
	binary.BigEndian.PutUint16(hdr[2:4], localSesID)
	return append(hdr, pppPayload...)
}

// buildAVPs serializes a list of AVPs into bytes per RFC 2661 §4.1 / RFC 3931
// §5.1. Each AVP is 6 bytes of header (M|H|rsvd|Length(10 bits) + Vendor ID +
// Attribute Type) followed by the Attribute Value. There is NO inter-AVP
// padding: neither RFC defines 4-byte alignment, and Wireshark's packet-l2tp.c
// advances by the declared Length only. Returns an error if any AVP exceeds
// the 10-bit Length max (1023).
func buildAVPs(avps []core.L2TPAVP) ([]byte, error) {
	var buf []byte
	for i, a := range avps {
		total := 6 + len(a.Value)
		if total > int(maxAVPLength) {
			return nil, fmt.Errorf("l2tp: AVP[%d] total length %d exceeds max %d (RFC 2661 §4.1, 10-bit Length field)", i, total, maxAVPLength)
		}
		// First word: bit 15 = M, bit 14 = H, bits 13-10 reserved (0), bits
		// 9-0 = Length. The Length is the 10-bit field covering the whole
		// AVP including the 6-byte header.
		var mh uint16
		if a.Mandatory {
			mh |= 0x8000
		}
		if a.Hidden {
			mh |= 0x4000
		}
		mh |= uint16(total) & 0x03FF
		buf = binary.BigEndian.AppendUint16(buf, mh)
		// Vendor ID (2 bytes).
		buf = binary.BigEndian.AppendUint16(buf, a.VendorID)
		// Attribute Type (2 bytes).
		buf = binary.BigEndian.AppendUint16(buf, a.AttrType)
		// Value.
		buf = append(buf, a.Value...)
		// No padding: RFC 2661 §4.1 / RFC 3931 §5.1 define no alignment
		// requirement, and Wireshark advances by declared Length only.
	}
	return buf, nil
}

// u16BE returns a 2-byte big-endian encoding of v.
func u16BE(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// u32BE returns a 4-byte big-endian encoding of v.
func u32BE(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// u64BE returns an 8-byte big-endian encoding of v.
func u64BE(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}