// Package pppoe implements the PPPoE (PPP over Ethernet, 以太网承载的点对点
// 协议, RFC 2516) planner. It emits the complete session lifecycle on the
// wire:
//
//	Discovery (RFC 2516 §5.1-5.4):
//	  PADI (client, broadcast, Session_ID 0x0000) -> PADO (server, AC-Name +
//	  AC-Cookie) -> PADR (client, echoes the AC-Cookie) -> PADS (server,
//	  assigns the Session_ID)
//	Session (RFC 1661):
//	  LCP Configure-Request/Ack (PPP Protocol 0xc021, MRU + Magic-Number +
//	  optional Auth-Protocol option), optional PAP (0xc023) / CHAP (0xc223)
//	  authentication, then IPv4 data frames (PPP Protocol 0x0021, inner
//	  IP/TCP/UDP).
//
// The Session_ID binds the PPP connection (RFC 2516 §5.4): Discovery frames
// carry 0x0000; PADS assigns the ID that every Session Data frame echoes.
// The core builder inserts the 6-byte PPPoE header and forces the EtherType
// to 0x8863/0x8864 from the per-packet PPPoEConfig; the planner only decides
// which packets to emit and what each carries.
package pppoe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Defaults per RFC 2516 / RFC 1661.
const (
	// DefaultSessionID is used when PPPoEConfig.SessionID is 0: PADS
	// assigns this deterministic value and the session phase echoes it.
	// Set SessionID explicitly to model distinct sessions.
	DefaultSessionID uint16 = 1

	// DefaultMRU is the LCP Maximum-Receive-Unit (RFC 1661 §6.1). The
	// PPPoE payload ceiling is 1492 (RFC 2516 §7: the 1500-byte MTU minus
	// the 6-byte PPPoE header minus the 2-byte PPP Protocol field).
	DefaultMRU uint16 = 1492

	// DefaultACName is the AC-Name tag value in PADO when unset.
	DefaultACName = "trafficgen"

	// DefaultCredentials is the PAP peer ID / CHAP name (and the PAP
	// password) when unset.
	DefaultCredentials = "trafficgen"

	// broadcastMAC is the PADI destination (RFC 2516 §5.2: the client
	// broadcasts PADI to all hosts on the Ethernet).
	broadcastMAC = "ff:ff:ff:ff:ff:ff"
)

// LCP codes (RFC 1661 §4.1).
const (
	lcpConfigureRequest byte = 1
	lcpConfigureAck     byte = 2
)

// LCP option types (RFC 1661 §6).
const (
	lcpOptMRU          byte = 1 // Maximum-Receive-Unit, value 2 bytes
	lcpOptAuthProtocol byte = 3 // Authentication-Protocol, value 2 bytes
	lcpOptMagicNumber  byte = 5 // Magic-Number, value 4 bytes
)

// PAP codes (RFC 1334 §2.1).
const (
	papAuthRequest byte = 1 // Authenticate-Request
	papAuthAck     byte = 2 // Authenticate-Ack
)

// CHAP codes (RFC 1994 §3).
const (
	chapChallenge byte = 1 // Challenge
	chapResponse  byte = 2 // Response
	chapSuccess   byte = 3 // Success
)

// chapValueLen is the CHAP challenge/response value length in bytes
// (RFC 1994 §3 uses a variable Value-Size; 16 matches the MD5 digest size
// of real CHAP clients).
const chapValueLen = 16

// Planner emits PPPoE packet configs for a complete session (Discovery +
// LCP + optional PAP/CHAP + IPv4 data plane).
type Planner struct{}

// NewPlanner returns a new PPPoE planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "pppoe" }

// Validate validates a PPPoE flow spec (read-only per validate_conventions.md
// §1.1: never mutate spec, never fill defaults -- Plan handles defaults).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.PPPoE == nil {
		return fmt.Errorf("pppoe: PPPoE config is required")
	}
	cfg := spec.PPPoE

	// Inner IPs must be valid IPv4 — PPP Protocol 0x0021 carries IPv4
	// only (RFC 1661 §6). Empty = planner default (filled by Plan).
	for _, pair := range []struct {
		name string
		val  string
	}{{"SrcIP", spec.SrcIP}, {"DstIP", spec.DstIP}} {
		if pair.val == "" {
			continue
		}
		parsed := net.ParseIP(pair.val)
		if parsed == nil {
			return fmt.Errorf("pppoe: %s %q is not a valid IP address", pair.name, pair.val)
		}
		if parsed.To4() == nil {
			return fmt.Errorf("pppoe: %s %q must be IPv4 (PPPoE carries IPv4 over PPP Protocol 0x0021, RFC 1661 §6)", pair.name, pair.val)
		}
	}

	// Auth selection (RFC 1661 §8).
	switch cfg.Auth {
	case "", "none", "pap", "chap":
		// ok
	default:
		return fmt.Errorf("pppoe: Auth %q not in supported list (allowed: none, pap, chap)", cfg.Auth)
	}

	// Inner IP protocol for the data plane.
	switch cfg.InnerProto {
	case 0, 6, 17:
		// ok (0 = UDP, or TCP when spec.TCP is set)
	default:
		return fmt.Errorf("pppoe: InnerProto %d not in supported list (allowed: 6=TCP, 17=UDP)", cfg.InnerProto)
	}

	if cfg.DataFrames < 0 {
		return fmt.Errorf("pppoe: DataFrames %d must be >= 0", cfg.DataFrames)
	}

	// Data frame direction.
	switch cfg.DataDirection {
	case "", "up", "down":
		// ok
	default:
		return fmt.Errorf("pppoe: DataDirection %q not in supported list (allowed: up, down)", cfg.DataDirection)
	}

	return nil
}

// Plan emits the complete PPPoE session for the flow. The client side is the
// "up" direction (spec.SrcMAC / spec.SrcIP); the server side is "down"
// (spec.DstMAC / spec.DstIP). All frames of one flow share one Session ID,
// binding the PPP connection (RFC 2516 §5.4).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	configChan := make(chan core.PacketConfig, 256)
	cfg := spec.PPPoE

	// Resolve the LCP Magic-Number before launching the goroutine (RFC
	// 1661 §6.13: "MUST be chosen randomly"). crypto/rand failure is
	// effectively impossible; fall back to a fixed value so the flow
	// still emits. Tests set MagicNumber explicitly for determinism.
	magic := cfg.MagicNumber
	if magic == 0 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err == nil {
			magic = binary.BigEndian.Uint32(b[:])
		} else {
			magic = 0x0900beef
		}
	}

	go func() {
		defer close(configChan)
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		now := time.Now()

		// Session state: the Session ID is assigned by PADS and echoed by
		// every Session Data frame (RFC 2516 §5.4). Discovery frames
		// (PADI/PADO/PADR/PADS) carry 0x0000.
		sessionID := cfg.SessionID
		if sessionID == 0 {
			sessionID = DefaultSessionID
		}
		mru := cfg.MRU
		if mru == 0 {
			mru = DefaultMRU
		}
		acName := cfg.ACName
		if acName == "" {
			acName = DefaultACName
		}
		user := cfg.Username
		if user == "" {
			user = DefaultCredentials
		}
		pass := cfg.Password
		if pass == "" {
			pass = DefaultCredentials
		}

		// MACs: client = up side, server = down side.
		upMAC, downMAC := spec.SrcMAC, spec.DstMAC
		if spec.SrcMAC == "" {
			upMAC = "aa:bb:cc:dd:ee:01"
		}
		if spec.DstMAC == "" {
			downMAC = "aa:bb:cc:dd:ee:02"
		}

		packetIndex := uint64(0)
		emit := func(cfgOut core.PacketConfig) bool {
			cfgOut.FlowID = flowID
			cfgOut.PacketIndex = packetIndex
			cfgOut.Timestamp = now
			select {
			case configChan <- cfgOut:
				packetIndex++
				return true
			case <-ctx.Done():
				return false
			}
		}

		// emitFrame builds and emits a single PPPoE frame. Discovery
		// frames (code != 0x00) carry TLV tags in PPPoE.DiscoveryTags
		// (the builder serializes them); Session Data frames with a
		// non-IPv4 PPP protocol carry the PPP control message in Payload;
		// Session Data frames with PPP Protocol 0x0021 carry the inner
		// L3/L4 built from l3/l4.
		emitFrame := func(direction, srcMAC, dstMAC string, code uint8, sessID uint16, pppProto uint16, tags []core.PPPoETag, payload []byte, l3 core.L3Config, l4 core.L4Config, withL3L4 bool) bool {
			var etherType uint16 = core.EtherTypePPPoEDiscovery
			if code == core.PPPoECodeSessionData {
				etherType = core.EtherTypePPPoESession
			}
			cfgOut := core.PacketConfig{
				Direction: direction,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: etherType,
					PPPoE: &core.PPPoEConfig{
						Code:          code,
						SessionID:     sessID,
						PPPProtocol:   pppProto,
						DiscoveryTags: tags,
					},
				},
				Payload: payload,
			}
			if withL3L4 {
				cfgOut.L3 = l3
				cfgOut.L4 = l4
			}
			return emit(cfgOut)
		}

		// ----- Discovery phase (RFC 2516 §5.1-5.4) -----
		if !cfg.SkipDiscovery {
			// PADI (RFC 2516 §5.2): client -> broadcast, Session_ID 0.
			// A zero-length Service-Name tag means "any service".
			padiTags := []core.PPPoETag{{Type: core.PPPoETagServiceName, Value: []byte(cfg.ServiceName)}}
			if !emitFrame("up", upMAC, broadcastMAC, core.PPPoECodePADI, 0, 0, padiTags, nil, core.L3Config{}, core.L4Config{}, false) {
				return
			}

			// PADO (RFC 2516 §5.3): server -> client, Session_ID 0,
			// carries AC-Name + AC-Cookie.
			padoTags := []core.PPPoETag{
				{Type: core.PPPoETagServiceName, Value: []byte(cfg.ServiceName)},
				{Type: core.PPPoETagACName, Value: []byte(acName)},
			}
			if len(cfg.Cookie) > 0 {
				padoTags = append(padoTags, core.PPPoETag{Type: core.PPPoETagACCookie, Value: cfg.Cookie})
			}
			if !emitFrame("down", downMAC, upMAC, core.PPPoECodePADO, 0, 0, padoTags, nil, core.L3Config{}, core.L4Config{}, false) {
				return
			}

			// PADR (RFC 2516 §5.4): client -> server, Session_ID 0,
			// echoes the AC-Cookie from PADO.
			padrTags := []core.PPPoETag{{Type: core.PPPoETagServiceName, Value: []byte(cfg.ServiceName)}}
			if len(cfg.Cookie) > 0 {
				padrTags = append(padrTags, core.PPPoETag{Type: core.PPPoETagACCookie, Value: cfg.Cookie})
			}
			if !emitFrame("up", upMAC, downMAC, core.PPPoECodePADR, 0, 0, padrTags, nil, core.L3Config{}, core.L4Config{}, false) {
				return
			}

			// PADS (RFC 2516 §5.4): server -> client, assigns the
			// Session_ID that all Session Data frames must echo.
			padsTags := []core.PPPoETag{{Type: core.PPPoETagServiceName, Value: []byte(cfg.ServiceName)}}
			if len(cfg.Cookie) > 0 {
				padsTags = append(padsTags, core.PPPoETag{Type: core.PPPoETagACCookie, Value: cfg.Cookie})
			}
			if !emitFrame("down", downMAC, upMAC, core.PPPoECodePADS, sessionID, 0, padsTags, nil, core.L3Config{}, core.L4Config{}, false) {
				return
			}
		}

		// ----- Session phase: LCP (RFC 1661 §4) -----
		// Configure-Request options: MRU (§6.1), Magic-Number (§6.13),
		// and the Auth-Protocol option (RFC 1334 §2.2 / RFC 1994 §3)
		// when authentication is enabled.
		lcpOpts := make([]byte, 0, 16)
		lcpOpts = append(lcpOpts, lcpOptMRU, 4)
		lcpOpts = binary.BigEndian.AppendUint16(lcpOpts, mru)
		lcpOpts = append(lcpOpts, lcpOptMagicNumber, 6)
		lcpOpts = binary.BigEndian.AppendUint32(lcpOpts, magic)
		var authProto uint16
		switch cfg.Auth {
		case "pap":
			authProto = core.PPPProtocolPAP
		case "chap":
			authProto = core.PPPProtocolCHAP
		}
		if authProto != 0 {
			lcpOpts = append(lcpOpts, lcpOptAuthProtocol, 4)
			lcpOpts = binary.BigEndian.AppendUint16(lcpOpts, authProto)
		}
		// Client sends Configure-Request; the server echoes a
		// Configure-Ack with the identical options (RFC 1661 §6.1).
		lcpReq := buildLCPMessage(lcpConfigureRequest, 1, lcpOpts)
		if !emitFrame("up", upMAC, downMAC, core.PPPoECodeSessionData, sessionID, core.PPPProtocolLCP, nil, lcpReq, core.L3Config{}, core.L4Config{}, false) {
			return
		}
		lcpAck := buildLCPMessage(lcpConfigureAck, 1, lcpOpts)
		if !emitFrame("down", downMAC, upMAC, core.PPPoECodeSessionData, sessionID, core.PPPProtocolLCP, nil, lcpAck, core.L3Config{}, core.L4Config{}, false) {
			return
		}

		// ----- Authentication (RFC 1334 PAP / RFC 1994 CHAP) -----
		switch cfg.Auth {
		case "pap":
			// Client -> server Authenticate-Request, then server ->
			// client Authenticate-Ack.
			papReq := buildPAPRequest(1, user, pass)
			if !emitFrame("up", upMAC, downMAC, core.PPPoECodeSessionData, sessionID, core.PPPProtocolPAP, nil, papReq, core.L3Config{}, core.L4Config{}, false) {
				return
			}
			papAck := buildPAPAck(1, "welcome")
			if !emitFrame("down", downMAC, upMAC, core.PPPoECodeSessionData, sessionID, core.PPPProtocolPAP, nil, papAck, core.L3Config{}, core.L4Config{}, false) {
				return
			}
		case "chap":
			// Server -> client Challenge, client -> server Response
			// (the planner echoes the challenge value — trafficgen
			// synthesizes the exchange and does not compute real MD5
			// digests, RFC 1994 §4.1), then server -> client Success.
			var value [chapValueLen]byte
			if _, err := rand.Read(value[:]); err != nil {
				for i := range value {
					value[i] = byte(i + 1)
				}
			}
			chal := buildCHAPChallenge(1, value[:], user)
			if !emitFrame("down", downMAC, upMAC, core.PPPoECodeSessionData, sessionID, core.PPPProtocolCHAP, nil, chal, core.L3Config{}, core.L4Config{}, false) {
				return
			}
			resp := buildCHAPResponse(1, value[:], user)
			if !emitFrame("up", upMAC, downMAC, core.PPPoECodeSessionData, sessionID, core.PPPProtocolCHAP, nil, resp, core.L3Config{}, core.L4Config{}, false) {
				return
			}
			succ := buildCHAPSuccess(1)
			if !emitFrame("down", downMAC, upMAC, core.PPPoECodeSessionData, sessionID, core.PPPProtocolCHAP, nil, succ, core.L3Config{}, core.L4Config{}, false) {
				return
			}
		}

		// ----- IPv4 data plane (RFC 1661 §6, PPP Protocol 0x0021) -----
		innerProto := cfg.InnerProto
		if innerProto == 0 {
			if spec.TCP != nil {
				innerProto = 6
			} else {
				innerProto = 17
			}
		}
		dataDir := cfg.DataDirection
		if dataDir == "" {
			dataDir = "up"
		}
		payload := cfg.DataPayload
		if payload == nil {
			payload = spec.Payload
		}
		frames := cfg.DataFrames
		if frames == 0 {
			frames = 1
		}
		ipidCounter := uint32(0)
		nextIPID := func() uint16 {
			ipidCounter++
			return uint16(ipidCounter)
		}
		for i := 0; i < frames; i++ {
			if err := ctx.Err(); err != nil {
				return
			}
			var srcMAC, dstMAC, srcIP, dstIP string
			if dataDir == "up" {
				srcMAC, dstMAC = upMAC, downMAC
				srcIP, dstIP = spec.SrcIP, spec.DstIP
			} else {
				srcMAC, dstMAC = downMAC, upMAC
				srcIP, dstIP = spec.DstIP, spec.SrcIP
			}
			l3 := core.L3Base(srcIP, dstIP, innerProto, spec.TTL, nextIPID(), spec)
			l4 := core.L4Config{
				Protocol: "udp",
				SrcPort:  spec.SrcPort,
				DstPort:  spec.DstPort,
			}
			if innerProto == 6 {
				l4.Protocol = "tcp"
				if spec.TCP != nil {
					l4.Seq = spec.TCP.Seq
					l4.Ack = spec.TCP.Ack
					l4.Flags = spec.TCP.Flags
					l4.WindowSize = spec.TCP.WindowSize
				}
			}
			if !emitFrame(dataDir, srcMAC, dstMAC, core.PPPoECodeSessionData, sessionID, core.PPPProtocolIPv4, nil, payload, l3, l4, true) {
				return
			}
		}
	}()

	return configChan, nil
}

// buildLCPMessage serializes an LCP packet (RFC 1661 §4): Code(1) +
// Identifier(1) + Length(2, counts code..data) + Options/Data.
func buildLCPMessage(code, id byte, data []byte) []byte {
	msg := make([]byte, 4+len(data))
	msg[0] = code
	msg[1] = id
	binary.BigEndian.PutUint16(msg[2:4], uint16(4+len(data)))
	copy(msg[4:], data)
	return msg
}

// buildPAPRequest serializes a PAP Authenticate-Request (RFC 1334 §2.1):
// Code=1, Identifier(1), Length(2), Peer-ID-Length(1), Peer-ID,
// Password-Length(1), Password.
func buildPAPRequest(id byte, user, pass string) []byte {
	total := 6 + len(user) + len(pass)
	msg := make([]byte, total)
	msg[0] = papAuthRequest
	msg[1] = id
	binary.BigEndian.PutUint16(msg[2:4], uint16(total))
	msg[4] = byte(len(user))
	copy(msg[5:], user)
	msg[5+len(user)] = byte(len(pass))
	copy(msg[6+len(user):], pass)
	return msg
}

// buildPAPAck serializes a PAP Authenticate-Ack (RFC 1334 §2.1): Code=2,
// Identifier(1), Length(2), Message-Length(1), Message.
func buildPAPAck(id byte, message string) []byte {
	total := 5 + len(message)
	msg := make([]byte, total)
	msg[0] = papAuthAck
	msg[1] = id
	binary.BigEndian.PutUint16(msg[2:4], uint16(total))
	msg[4] = byte(len(message))
	copy(msg[5:], message)
	return msg
}

// buildCHAPChallenge serializes a CHAP Challenge (RFC 1994 §3): Code=1,
// Identifier(1), Length(2), Value-Size(1), Value, Name.
func buildCHAPChallenge(id byte, value []byte, name string) []byte {
	total := 5 + len(value) + len(name)
	msg := make([]byte, total)
	msg[0] = chapChallenge
	msg[1] = id
	binary.BigEndian.PutUint16(msg[2:4], uint16(total))
	msg[4] = byte(len(value))
	copy(msg[5:], value)
	copy(msg[5+len(value):], name)
	return msg
}

// buildCHAPResponse serializes a CHAP Response (RFC 1994 §3): Code=2 with
// the same layout as the Challenge.
func buildCHAPResponse(id byte, value []byte, name string) []byte {
	total := 5 + len(value) + len(name)
	msg := make([]byte, total)
	msg[0] = chapResponse
	msg[1] = id
	binary.BigEndian.PutUint16(msg[2:4], uint16(total))
	msg[4] = byte(len(value))
	copy(msg[5:], value)
	copy(msg[5+len(value):], name)
	return msg
}

// buildCHAPSuccess serializes a CHAP Success (RFC 1994 §3): Code=3,
// Identifier(1), Length(2), no message.
func buildCHAPSuccess(id byte) []byte {
	msg := make([]byte, 4)
	msg[0] = chapSuccess
	msg[1] = id
	binary.BigEndian.PutUint16(msg[2:4], 4)
	return msg
}
