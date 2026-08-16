// Package mqtt implements the MQTT protocol planner (MQTT 3.1.1 / MQTT 5.0).
// See types.go for data structures and builder.go for packet builders.
package mqtt

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort is the default MQTT TCP port (IANA: mqtt/tcp 1883).
	DefaultPort = 1883

	// DefaultTTL used when spec.TTL is zero.
	DefaultTTL = 64

	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS (1460).
	DefaultMSS = 1460

	// MinMSS (最小MSS) per RFC 879.
	MinMSS = 536

	// DefaultKeepAlive is the default CONNECT Keep Alive field in seconds.
	DefaultKeepAlive = 60
)

// MQTT Packet Type constants.
const (
	TypeCONNECT     = 1
	TypeCONNACK     = 2
	TypePUBLISH     = 3
	TypePUBACK      = 4
	TypePUBREC      = 5
	TypePUBREL      = 6
	TypePUBCOMP     = 7
	TypeSUBSCRIBE   = 8
	TypeSUBACK      = 9
	TypeUNSUBSCRIBE = 10
	TypeUNSUBACK    = 11
	TypePINGREQ     = 12
	TypePINGRESP    = 13
	TypeDISCONNECT  = 14
	TypeAUTH        = 15
)

// TCP flags used by the planner (same as other protocols).
const (
	tcpSYN    = 0x02
	tcpSYNACK = 0x12
	tcpACK    = 0x10
	tcpPSHACK = 0x18
	tcpFINACK = 0x11
)

// Planner implements the MQTT protocol planner.
type Planner struct{}

var clientIDCounter atomic.Uint64

// NewPlanner creates a new MQTT planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string { return "mqtt" }

// Validate validates an MQTT flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("mqtt: invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("mqtt: invalid destination IP: %s", spec.DstIP)
		}
	}
	if spec.MQTT == nil {
		return fmt.Errorf("mqtt: MQTTConfig is required")
	}

	cfg := spec.MQTT
	version := cfg.Version
	if version == 0 {
		version = 4
	}
	if version != 4 && version != 5 {
		return fmt.Errorf("mqtt: invalid version %d (allowed: 4, 5)", cfg.Version)
	}

	if cfg.KeepAlive != nil && (*cfg.KeepAlive < 0 || *cfg.KeepAlive > 65535) {
		return fmt.Errorf("mqtt: keep_alive must be between 0 and 65535")
	}

	if err := validateUTF8("client_id", cfg.ClientID); err != nil {
		return err
	}
	if err := validateUTF8("username", cfg.Username); err != nil {
		return err
	}
	if err := validateUTF8("password", cfg.Password); err != nil {
		return err
	}

	if version == 4 && cfg.Username == "" && cfg.Password != "" {
		return fmt.Errorf("mqtt: username required when password is set (3.1.1)")
	}

	if cfg.Will != nil {
		if cfg.Will.Topic == "" {
			return fmt.Errorf("mqtt: will topic is required")
		}
		if err := validateUTF8("will topic", cfg.Will.Topic); err != nil {
			return err
		}
		if len(cfg.Will.Payload) > 65535 {
			return fmt.Errorf("mqtt: will payload exceeds 65535 bytes")
		}
		if cfg.Will.QoS < 0 || cfg.Will.QoS > 2 {
			return fmt.Errorf("mqtt: invalid will qos %d (allowed: 0, 1, 2)", cfg.Will.QoS)
		}
		if cfg.Will.DelayInterval < 0 {
			return fmt.Errorf("mqtt: will delay_interval must be >= 0")
		}
		if version == 4 && cfg.Will.DelayInterval != 0 {
			return fmt.Errorf("mqtt: will delay_interval is 5.0 only")
		}
	}

	if err := validateConnectAckCode(version, cfg.ConnectAckCode); err != nil {
		return err
	}

	if cfg.DisconnectReason != nil {
		if version == 4 {
			return fmt.Errorf("mqtt: disconnect_reason is 5.0 only")
		}
		if !validDisconnectReason(*cfg.DisconnectReason) {
			return fmt.Errorf("mqtt: invalid disconnect_reason 0x%02X for version 5.0", *cfg.DisconnectReason)
		}
	}

	// Track Topic Alias mapping state across messages: a PUBLISH with an
	// empty Topic Name is only legal when a prior message in the same flow
	// established the alias with a non-empty topic (design T-073/T-074).
	// Additionally (rule §8.1 10b, T-074b): using a Topic Alias (0x23) at
	// all requires CONNECT to have declared a Topic Alias Maximum (0x22)
	// covering the alias value — absent 0x22, the maximum defaults to 0,
	// meaning the sender accepts no aliases (5.0 §3.1.2.11.5). This check
	// was previously missing: an alias-bearing PUBLISH on a connection
	// that declared no maximum passed validation and put a
	// protocol-invalid packet on the wire.
	aliasMax := 0
	if version == 5 {
		for _, prop := range cfg.Properties {
			if prop.Identifier == 0x22 { // Topic Alias Maximum
				if n, err := parseUint(prop.Value, 16); err == nil && int(n) > aliasMax {
					aliasMax = int(n)
				}
			}
		}
	}
	if err := validateMessageAliases(version, cfg.Messages, aliasMax); err != nil {
		return err
	}

	cleanSession := true
	if cfg.CleanSession != nil {
		cleanSession = *cfg.CleanSession
	}
	if cleanSession && cfg.ConnectAckSessionPresent {
		return fmt.Errorf("mqtt: clean_session=true and session_present=true are mutually exclusive")
	}
	if cfg.ConnectAckCode != 0 && cfg.ConnectAckSessionPresent {
		return fmt.Errorf("mqtt: session_present=true is invalid when connect_ack_code != 0")
	}

	for _, sub := range cfg.Subscriptions {
		if len(sub.Filters) == 0 {
			return fmt.Errorf("mqtt: subscriptions filters cannot be empty")
		}
		if len(sub.AckReasonCodes) > 0 && len(sub.AckReasonCodes) != len(sub.Filters) {
			return fmt.Errorf("mqtt: ack_reason_codes length must match filters length")
		}
		for _, code := range sub.AckReasonCodes {
			if !validSubackCode(version, code) {
				return fmt.Errorf("mqtt: invalid SUBACK reason code 0x%02X for version %d", code, version)
			}
		}
		if version == 4 && len(sub.Properties) > 0 {
			return fmt.Errorf("mqtt: subscription properties are 5.0 only")
		}
		if version == 5 && len(sub.Properties) > 0 {
			if err := validateProperties(0x82, sub.Properties, ""); err != nil {
				return fmt.Errorf("mqtt: subscription: %w", err)
			}
		}
		for _, f := range sub.Filters {
			if err := validateTopicFilter(version, f.Filter); err != nil {
				return fmt.Errorf("mqtt: invalid subscription filter: %w", err)
			}
			if f.QoS < 0 || f.QoS > 2 {
				return fmt.Errorf("mqtt: invalid subscription qos %d", f.QoS)
			}
			if version == 4 && (f.NoLocal || f.RetainAsPublished || f.RetainHandling != 0) {
				return fmt.Errorf("mqtt: subscription options are 5.0 only")
			}
			if f.RetainHandling < 0 || f.RetainHandling > 2 {
				return fmt.Errorf("mqtt: invalid retain_handling %d", f.RetainHandling)
			}
		}
	}

	for _, msg := range cfg.Messages {
		if err := validateMessage(version, msg); err != nil {
			return err
		}
	}

	if version == 4 && len(cfg.Properties) > 0 {
		return fmt.Errorf("mqtt: properties are 5.0 only")
	}
	if version == 5 && len(cfg.Properties) > 0 {
		if err := validateProperties(0x10, cfg.Properties, ""); err != nil {
			return err
		}
	}
	if version == 4 && len(cfg.ConnackProperties) > 0 {
		return fmt.Errorf("mqtt: connack_properties are 5.0 only")
	}
	if version == 5 && len(cfg.ConnackProperties) > 0 {
		if err := validateProperties(0x20, cfg.ConnackProperties, ""); err != nil {
			return err
		}
	}

	seenClientIDs := make(map[string]bool)
	for i, session := range cfg.Sessions {
		if session.ClientID != "" {
			if seenClientIDs[session.ClientID] {
				return fmt.Errorf("mqtt: duplicate client_id in sessions[%d]", i)
			}
			seenClientIDs[session.ClientID] = true
		}
		if session.Will != nil {
			if session.Will.Topic == "" {
				return fmt.Errorf("mqtt: session[%d] will topic is required", i)
			}
			// Bug fix: session-level Will validation previously skipped UTF-8
			// check on topic, payload length limit (65535B), DelayInterval
			// sign check, and version=4 delay rejection — all enforced at
			// top-level. Mirror top-level checks so a session cannot bypass
			// validation by overriding Will.
			if err := validateUTF8("will topic", session.Will.Topic); err != nil {
				return fmt.Errorf("mqtt: session[%d] %w", i, err)
			}
			if len(session.Will.Payload) > 65535 {
				return fmt.Errorf("mqtt: session[%d] will payload exceeds 65535 bytes", i)
			}
			if session.Will.QoS < 0 || session.Will.QoS > 2 {
				return fmt.Errorf("mqtt: session[%d] invalid will qos", i)
			}
			if session.Will.DelayInterval < 0 {
				return fmt.Errorf("mqtt: session[%d] will delay_interval must be >= 0", i)
			}
			if version == 4 && session.Will.DelayInterval != 0 {
				return fmt.Errorf("mqtt: session[%d] will delay_interval is 5.0 only", i)
			}
		}
		for _, msg := range session.Messages {
			if err := validateMessage(version, msg); err != nil {
				return fmt.Errorf("mqtt: session[%d] %w", i, err)
			}
		}
		for _, sub := range session.Subscriptions {
			if len(sub.Filters) == 0 {
				return fmt.Errorf("mqtt: session[%d] subscriptions filters cannot be empty", i)
			}
			if len(sub.AckReasonCodes) > 0 && len(sub.AckReasonCodes) != len(sub.Filters) {
				return fmt.Errorf("mqtt: session[%d] ack_reason_codes length must match filters length", i)
			}
			for _, code := range sub.AckReasonCodes {
				if !validSubackCode(version, code) {
					return fmt.Errorf("mqtt: session[%d] invalid SUBACK reason code 0x%02X", i, code)
				}
			}
			if version == 4 && len(sub.Properties) > 0 {
				return fmt.Errorf("mqtt: session[%d] subscription properties are 5.0 only", i)
			}
			if version == 5 && len(sub.Properties) > 0 {
				if err := validateProperties(0x82, sub.Properties, ""); err != nil {
					return fmt.Errorf("mqtt: session[%d] subscription: %w", i, err)
				}
			}
			for _, f := range sub.Filters {
				if err := validateTopicFilter(version, f.Filter); err != nil {
					return fmt.Errorf("mqtt: session[%d] invalid subscription filter: %w", i, err)
				}
				if f.QoS < 0 || f.QoS > 2 || f.RetainHandling < 0 || f.RetainHandling > 2 {
					return fmt.Errorf("mqtt: session[%d] invalid subscription options", i)
				}
				if version == 4 && (f.NoLocal || f.RetainAsPublished || f.RetainHandling != 0) {
					return fmt.Errorf("mqtt: session[%d] subscription options are 5.0 only", i)
				}
			}
		}
		merged := mergeSession(cfg, session)
		if err := validateMergedSession(version, merged, i); err != nil {
			return err
		}
	}

	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < MinMSS {
		return fmt.Errorf("mqtt: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
	}

	return nil
}

func validSubackCode(version, code int) bool {
	if version == 4 {
		return code == 0 || code == 1 || code == 2 || code == 0x80
	}
	switch code {
	case 0, 1, 2, 0x80, 0x83, 0x87, 0x8F, 0x91, 0x97, 0x9E, 0xA1, 0xA2:
		return true
	default:
		return false
	}
}

func validateUTF8(field, value string) error {
	if len(value) > 65535 {
		return fmt.Errorf("mqtt: %s exceeds 65535 bytes", field)
	}
	for _, r := range value {
		if r == 0 || (r >= 0xD800 && r <= 0xDFFF) {
			return fmt.Errorf("mqtt: %s contains forbidden UTF-8 code point", field)
		}
	}
	return nil
}

func validateMergedSession(version int, cfg *MQTTConfig, idx int) error {
	if cfg.KeepAlive != nil && (*cfg.KeepAlive < 0 || *cfg.KeepAlive > 65535) {
		return fmt.Errorf("mqtt: session[%d] keep_alive must be between 0 and 65535", idx)
	}
	if version == 4 && cfg.Username == "" && cfg.Password != "" {
		return fmt.Errorf("mqtt: session[%d] username required when password is set", idx)
	}
	// Bug fix: merged session validation previously skipped Will and
	// subscription/message checks. After merge, the effective config is
	// what gets emitted, so every constraint the top-level Validate()
	// enforces must be re-checked on the merged result. A session that
	// provides its own Will/Subscriptions/Messages must satisfy the same
	// rules as the top-level config; the per-session pre-merge loop
	// already checks session fields, but the merged config may combine
	// session overrides with top-level defaults in ways that the
	// pre-merge loop doesn't see (e.g. session.Will replacing top Will).
	if cfg.Will != nil {
		if cfg.Will.Topic == "" {
			return fmt.Errorf("mqtt: session[%d] merged will topic is required", idx)
		}
		if err := validateUTF8("will topic", cfg.Will.Topic); err != nil {
			return fmt.Errorf("mqtt: session[%d] merged %w", idx, err)
		}
		if len(cfg.Will.Payload) > 65535 {
			return fmt.Errorf("mqtt: session[%d] merged will payload exceeds 65535 bytes", idx)
		}
		if cfg.Will.QoS < 0 || cfg.Will.QoS > 2 {
			return fmt.Errorf("mqtt: session[%d] merged invalid will qos %d", idx, cfg.Will.QoS)
		}
		if cfg.Will.DelayInterval < 0 {
			return fmt.Errorf("mqtt: session[%d] merged will delay_interval must be >= 0", idx)
		}
		if version == 4 && cfg.Will.DelayInterval != 0 {
			return fmt.Errorf("mqtt: session[%d] merged will delay_interval is 5.0 only", idx)
		}
	}
	for j, sub := range cfg.Subscriptions {
		if len(sub.Filters) == 0 {
			return fmt.Errorf("mqtt: session[%d] merged subscriptions[%d] filters cannot be empty", idx, j)
		}
		if len(sub.AckReasonCodes) > 0 && len(sub.AckReasonCodes) != len(sub.Filters) {
			return fmt.Errorf("mqtt: session[%d] merged subscriptions[%d] ack_reason_codes length must match filters length", idx, j)
		}
	}
	if version == 4 && len(cfg.Properties) > 0 {
		return fmt.Errorf("mqtt: session[%d] properties are 5.0 only", idx)
	}
	if version == 5 {
		if err := validateProperties(0x10, cfg.Properties, ""); err != nil {
			return fmt.Errorf("mqtt: session[%d]: %w", idx, err)
		}
		if err := validateProperties(0x20, cfg.ConnackProperties, ""); err != nil {
			return fmt.Errorf("mqtt: session[%d]: %w", idx, err)
		}
	}
	// Bug fix (T-074b): session messages bypassed the flow-level Topic Alias
	// rules — a session PUBLISH carrying 0x23 without a declared 0x22
	// maximum passed validation. Re-run the same alias checks on the merged
	// config (its Properties are the effective CONNECT properties).
	aliasMax := 0
	for _, prop := range cfg.Properties {
		if prop.Identifier == 0x22 {
			if n, err := parseUint(prop.Value, 16); err == nil && int(n) > aliasMax {
				aliasMax = int(n)
			}
		}
	}
	if err := validateMessageAliases(version, cfg.Messages, aliasMax); err != nil {
		return fmt.Errorf("mqtt: session[%d]: %w", idx, err)
	}
	return nil
}

func validDisconnectReason(code int) bool {
	// DISCONNECT 5.0 Reason Code whitelist (design §2.12): 0, 4,
	// 128-132, 135, 137, 139-144, 147-162.
	switch code {
	case 0, 4, 128, 129, 130, 131, 132, 135, 137, 139, 140, 141, 142,
		143, 144, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156,
		157, 158, 159, 160, 161, 162:
		return true
	default:
		return false
	}
}

func validateConnectAckCode(version, code int) error {
	if version == 0 || version == 4 {
		if code < 0 || code > 5 {
			return fmt.Errorf("mqtt: invalid connect_ack_code %d for version 3.1.1 (allowed: 0-5)", code)
		}
	} else if version == 5 {
		validCodes := map[int]bool{
			0: true, 128: true, 129: true, 130: true, 131: true,
			132: true, 133: true, 134: true, 135: true, 136: true,
			137: true, 138: true, 140: true, 144: true, 149: true,
			151: true, 153: true, 154: true, 155: true, 156: true,
			157: true, 159: true,
		}
		if !validCodes[code] {
			return fmt.Errorf("mqtt: invalid connect_ack_code %d for version 5.0", code)
		}
	}
	return nil
}

func validateTopicFilter(version int, filter string) error {
	if filter == "" {
		return fmt.Errorf("empty topic filter")
	}
	if err := validateUTF8("topic filter", filter); err != nil {
		return err
	}
	for i, c := range filter {
		if c == '#' {
			if i != len(filter)-1 || (i > 0 && filter[i-1] != '/') {
				return fmt.Errorf("'#' wildcard must occupy the final topic level")
			}
		}
		if c == '+' && (i > 0 && filter[i-1] != '/' || i+1 < len(filter) && filter[i+1] != '/') {
			return fmt.Errorf("'+' wildcard must occupy an entire topic level")
		}
	}
	if len(filter) > 7 && filter[:7] == "$share/" {
		if version == 4 {
			return fmt.Errorf("shared subscriptions are 5.0 only")
		}
		parts := strings.Split(filter[7:], "/")
		if len(parts) < 2 {
			return fmt.Errorf("shared subscription must have group and filter")
		}
		group := parts[0]
		if group == "" {
			return fmt.Errorf("shared subscription group cannot be empty")
		}
		for _, c := range group {
			if c == '/' || c == '+' || c == '#' {
				return fmt.Errorf("shared subscription group cannot contain '/', '+', or '#'")
			}
		}
	}
	return nil
}

func validateMessage(version int, msg MQTTMessage) error {
	if msg.QoS < 0 || msg.QoS > 2 {
		return fmt.Errorf("mqtt: invalid message qos %d (allowed: 0, 1, 2)", msg.QoS)
	}
	if msg.DUP && msg.QoS == 0 {
		return fmt.Errorf("mqtt: DUP flag is invalid for QoS 0")
	}
	if msg.Direction != "" && msg.Direction != "up" && msg.Direction != "down" {
		return fmt.Errorf("mqtt: invalid message direction %q (allowed: up, down)", msg.Direction)
	}
	if msg.Topic == "" {
		// Empty topic is only legal in 5.0 with an established Topic Alias
		// (checked by the caller with flow-level alias state, T-073/T-074).
		// validateMessage itself cannot decide — it lacks the alias history.
		if version != 5 {
			return fmt.Errorf("mqtt: message topic cannot be empty (without topic alias)")
		}
	}
	if err := validateUTF8("message topic", msg.Topic); err != nil {
		return err
	}
	for _, c := range msg.Topic {
		if c == '#' || c == '+' {
			return fmt.Errorf("mqtt: PUBLISH topic cannot contain wildcards")
		}
	}
	if len(msg.Topic) > 65535 {
		return fmt.Errorf("mqtt: topic length exceeds 65535")
	}
	if msg.QoS == 0 && msg.PacketID != 0 {
		return fmt.Errorf("mqtt: QoS 0 messages cannot have packet_id")
	}
	if version == 4 && len(msg.Properties) > 0 {
		return fmt.Errorf("mqtt: message properties are 5.0 only")
	}
	if version == 5 && len(msg.Properties) > 0 {
		// Bug fix (T-026): an omitted direction field ("") means the
		// default "up", but validateProperties only rejected 0x0B for
		// the literal string "up" — a default-direction PUBLISH carrying
		// a Subscription Identifier passed validation and put a
		// client-only property on the wire. Normalize "" → "up" so the
		// MQTT-3.3.4-6 prohibition cannot be bypassed.
		dir := msg.Direction
		if dir == "" {
			dir = "up"
		}
		if err := validateProperties(0x30, msg.Properties, dir); err != nil {
			return err
		}
	}
	return nil
}

// validateProperties validates MQTT 5.0 properties against the
// property-identifier × packet-type whitelist (design §8.4), duplicate
// rules (§2.14), and per-format value validation (§8.5).
// packetType: 0x10 = CONNECT, 0x30 = PUBLISH, 0x20 = CONNACK, 0x82 = SUBSCRIBE,
// 0x90 = SUBACK, 0xE0 = DISCONNECT, 0x01 = Will Properties.
func validateProperties(packetType int, props []MQTTProperty, direction string) error {
	// Property Identifier × packet type whitelist (design §8.4).
	whitelist := map[int]map[int]bool{
		0x10: { // CONNECT
			0x11: true, 0x15: true, 0x16: true, 0x17: true, 0x19: true,
			0x21: true, 0x22: true, 0x26: true, 0x27: true,
		},
		0x20: { // CONNACK
			0x11: true, 0x12: true, 0x13: true, 0x15: true, 0x16: true,
			0x1A: true, 0x1C: true, 0x1F: true, 0x21: true, 0x22: true,
			0x24: true, 0x25: true, 0x26: true, 0x27: true, 0x28: true,
			0x29: true, 0x2A: true,
		},
		0x30: { // PUBLISH
			0x01: true, 0x02: true, 0x03: true, 0x08: true, 0x09: true,
			0x0B: true, 0x23: true, 0x26: true,
		},
		0x01: { // Will Properties
			0x01: true, 0x02: true, 0x03: true, 0x08: true, 0x09: true,
			0x18: true, 0x26: true,
		},
		0x82: { // SUBSCRIBE
			0x0B: true, 0x26: true,
		},
		0x90: { // SUBACK
			0x1F: true, 0x26: true,
		},
		0xE0: { // DISCONNECT
			0x11: true, 0x1C: true, 0x1F: true, 0x26: true,
		},
	}
	// PUBACK/PUBREC/PUBREL/PUBCOMP share {0x1F, 0x26}.
	if packetType >= 0x40 && packetType <= 0x70 {
		whitelist[packetType] = map[int]bool{0x1F: true, 0x26: true}
	}

	allowed := whitelist[packetType]
	seen := make(map[int]bool)
	for i, prop := range props {
		id := prop.Identifier
		if id < 0 || id > 255 {
			return fmt.Errorf("mqtt: invalid property identifier %d", id)
		}
		// Whitelist check.
		if !allowed[id] {
			return fmt.Errorf("mqtt: property 0x%02X not allowed in packet type 0x%02X", id, packetType)
		}
		// Duplicate check: User Property (0x26) may repeat; Subscription
		// Identifier (0x0B) may repeat ONLY in down PUBLISH (broker→client
		// forwarding with multiple matching subscriptions); SUBSCRIBE must
		// not repeat 0x0B.
		if id != 0x26 {
			if id == 0x0B {
				if packetType == 0x82 { // SUBSCRIBE: no repeats
					if seen[id] {
						return fmt.Errorf("mqtt: subscription identifier cannot repeat in SUBSCRIBE")
					}
				} else if packetType == 0x30 {
					if direction == "up" {
						return fmt.Errorf("mqtt: up PUBLISH cannot carry subscription identifier")
					}
					// down PUBLISH: repeats allowed, no duplicate check.
				} else if seen[id] {
					return fmt.Errorf("mqtt: duplicate property identifier 0x%02X", id)
				}
			} else if seen[id] {
				return fmt.Errorf("mqtt: duplicate property identifier 0x%02X", id)
			}
			if id != 0x0B || packetType != 0x30 || direction != "down" {
				seen[id] = true
			}
		}
		// Per-format value validation.
		if err := validatePropertyValue(prop, i); err != nil {
			return err
		}
		// Bug fix: per-identifier constraints were previously missing for
		// VBI-encoded properties. MQTT 5.0 §3.3.2.3.8 (Subscription
		// Identifier 0x0B) forbids the value 0 — it is reserved as a
		// "no subscription" sentinel. The generic vbi format check only
		// validates the numeric range (0-268435455), so a value of "0"
		// passed validation and produced a wire-format 0x00 byte that
		// the broker would reject as a protocol error.
		if id == 0x0B && prop.Value == "0" {
			return fmt.Errorf("mqtt: property[%d] subscription identifier cannot be 0", i)
		}
	}
	return nil
}

// validateMessageAliases enforces the flow-level Topic Alias rules
// (design §8.1 rule 9 + rule 10b) across a message list:
//   - rule 9 (T-073): a PUBLISH with an empty Topic Name is only legal when
//     a prior message established the alias with a non-empty topic;
//   - rule 10b (T-074b): any use of Topic Alias (0x23) requires CONNECT to
//     have declared Topic Alias Maximum (0x22) ≥ the alias value, and a
//     declared maximum of 0 (absent 0x22) forbids aliases entirely.
//
// Messages are validated in order because alias establishment is
// order-dependent. connectProps carries the merged CONNECT properties
// (0x22 may be declared at top level or per session).
func validateMessageAliases(version int, messages []core.MQTTMessage, aliasMax int) error {
	if version != 5 {
		return nil
	}
	aliasEstablished := make(map[int]bool)
	for _, msg := range messages {
		if err := validateMessage(version, msg); err != nil {
			return err
		}
		for _, prop := range msg.Properties {
			if prop.Identifier != 0x23 { // Topic Alias
				continue
			}
			alias, err := parseUint(prop.Value, 16)
			if err != nil {
				continue // format error already reported by validateProperties
			}
			if aliasMax == 0 {
				return fmt.Errorf("mqtt: topic alias %d used without CONNECT Topic Alias Maximum (0x22 must be declared, absent defaults to 0)", alias)
			}
			if int(alias) > aliasMax {
				return fmt.Errorf("mqtt: topic alias %d exceeds declared Topic Alias Maximum %d", alias, aliasMax)
			}
			if msg.Topic == "" && !aliasEstablished[int(alias)] {
				return fmt.Errorf("mqtt: empty topic with unestablished topic alias %d (first alias use must carry a topic name)", alias)
			}
			if msg.Topic != "" {
				aliasEstablished[int(alias)] = true
			}
		}
	}
	return nil
}

// validatePropertyValue validates a single property's value per its format.
func validatePropertyValue(prop MQTTProperty, idx int) error {
	format := prop.Format
	if format == "" {
		format = "string"
	}
	switch format {
	case "byte":
		n, err := parseUint(prop.Value, 8)
		if err != nil {
			return fmt.Errorf("mqtt: property[%d] byte value %q: %v", idx, prop.Value, err)
		}
		_ = n
	case "uint16":
		if _, err := parseUint(prop.Value, 16); err != nil {
			return fmt.Errorf("mqtt: property[%d] uint16 value %q: %v", idx, prop.Value, err)
		}
	case "uint32":
		if _, err := parseUint(prop.Value, 32); err != nil {
			return fmt.Errorf("mqtt: property[%d] uint32 value %q: %v", idx, prop.Value, err)
		}
	case "vbi":
		if _, err := parseUint(prop.Value, 32); err != nil {
			return fmt.Errorf("mqtt: property[%d] vbi value %q: %v", idx, prop.Value, err)
		}
		n, _ := parseUint(prop.Value, 32)
		if n > 268435455 {
			return fmt.Errorf("mqtt: property[%d] vbi value %q exceeds 268435455", idx, prop.Value)
		}
	case "string":
		if len(prop.Value) > 65535 {
			return fmt.Errorf("mqtt: property[%d] string exceeds 65535 bytes", idx)
		}
		for _, r := range prop.Value {
			if r == 0 {
				return fmt.Errorf("mqtt: property[%d] string contains U+0000", idx)
			}
			if r >= 0xD800 && r <= 0xDFFF {
				return fmt.Errorf("mqtt: property[%d] string contains surrogate", idx)
			}
		}
	case "binary":
		if len(prop.Value)%2 != 0 {
			return fmt.Errorf("mqtt: property[%d] binary hex must have even length", idx)
		}
		for i := 0; i < len(prop.Value); i++ {
			if !isHexDigit(prop.Value[i]) {
				return fmt.Errorf("mqtt: property[%d] binary value is not valid hex", idx)
			}
		}
		if len(prop.Value)/2 > 65535 {
			return fmt.Errorf("mqtt: property[%d] binary exceeds 65535 bytes", idx)
		}
	case "stringpair":
		parts := strings.SplitN(prop.Value, "\x00", 2)
		if len(parts) != 2 {
			return fmt.Errorf("mqtt: property[%d] stringpair must contain NUL separator", idx)
		}
		if len(parts[0]) > 65535 || len(parts[1]) > 65535 {
			return fmt.Errorf("mqtt: property[%d] stringpair part exceeds 65535 bytes", idx)
		}
	default:
		return fmt.Errorf("mqtt: unknown property format %q", prop.Format)
	}
	return nil
}

// parseUint parses a decimal string into an unsigned integer of the given
// bit width.
func parseUint(s string, bits int) (uint64, error) {
	var v uint64
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a decimal number")
		}
		d := uint64(c - '0')
		if v > (1<<63-1)/10 {
			return 0, fmt.Errorf("overflow")
		}
		v = v*10 + d
	}
	max := uint64(1<<bits) - 1
	if bits == 32 {
		max = 4294967295
	}
	if bits == 8 {
		max = 255
	}
	if bits == 16 {
		max = 65535
	}
	if v > max {
		return 0, fmt.Errorf("value %s exceeds %d-bit range", s, bits)
	}
	return v, nil
}

// isHexDigit reports whether c is a hex digit.
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Plan generates packet configs for an MQTT flow (or one flow per session
// when Sessions[] is set — each session gets an independent 4-tuple and
// FlowID).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	// Multi-session auto source-port allocation must be validated on the
	// synchronous path. The previous code performed the bound check inside
	// emitAll (running in a goroutine) and discarded its error, so an
	// overflowing src_port silently produced colliding 4-tuples instead of
	// failing the task (Bug #4 regression test).
	if err := validateAutoSrcPorts(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)
		_ = emitAll(ctx, spec, configChan)
	}()

	return configChan, nil
}

// validateAutoSrcPorts rejects multi-session configs whose auto-incremented
// source ports would overflow uint16 or fall below the ephemeral minimum.
// Only applies when the user did not explicitly set src_port (auto-inc mode).
func validateAutoSrcPorts(spec core.FlowSpec) error {
	cfg := spec.MQTT
	if cfg == nil || len(cfg.Sessions) == 0 || spec.HasExplicitSrcPort {
		return nil
	}
	srcPort := spec.SrcPort
	numSessions := len(cfg.Sessions)
	maxPort := uint16(65535)
	needed := uint32(srcPort) + uint32(numSessions) - 1
	if needed > uint32(maxPort) {
		return fmt.Errorf("mqtt: auto source port range overflow: src_port=%d + %d sessions exceeds 65535", srcPort, numSessions)
	}
	if srcPort < 1024 {
		return fmt.Errorf("mqtt: auto source port %d below ephemeral minimum 1024", srcPort)
	}
	return nil
}

// emitAll emits one flow per MQTT session. When Sessions[] is empty, a
// single flow is emitted using the top-level config directly.
func emitAll(ctx context.Context, spec core.FlowSpec, configChan chan<- core.PacketConfig) error {
	cfg := spec.MQTT
	if cfg == nil {
		return fmt.Errorf("mqtt: config is nil")
	}

	if len(cfg.Sessions) == 0 {
		if spec.DstPort == 0 {
			spec.DstPort = DefaultPort
		}
		return emitSessionFlow(ctx, spec, cfg, -1, configChan)
	}

	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	srcPort := spec.SrcPort
	// Auto-incremented source ports are validated synchronously in Plan
	// (validateAutoSrcPorts) so the overflow/below-ephemeral errors reach
	// the caller; the loop below only assigns the per-session ports.
	for i := range cfg.Sessions {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
		s := mergeSession(cfg, cfg.Sessions[i])
		// Each session gets a distinct ephemeral source port unless the
		// user explicitly overrode it (HasExplicitSrcPort=false → auto-inc).
		if cfg.Sessions[i].SrcPort != 0 {
			spec.SrcPort = cfg.Sessions[i].SrcPort
		} else if !spec.HasExplicitSrcPort {
			spec.SrcPort = srcPort + uint16(i)
		}
		if cfg.Sessions[i].DstPort != 0 {
			spec.DstPort = cfg.Sessions[i].DstPort
		} else if spec.DstPort == 0 {
			spec.DstPort = DefaultPort
		}
		// Guard against SrcPort == DstPort (would cause TCP self-talk).
		if spec.SrcPort == spec.DstPort {
			return fmt.Errorf("mqtt: session[%d] src_port %d collides with dst_port", i, spec.SrcPort)
		}
		if err := emitSessionFlow(ctx, spec, s, i, configChan); err != nil {
			return err
		}
	}
	return nil
}

// mergeSession merges top-level config with a session's overrides following
// the inheritance rules: scalar fields inherit when the session field is
// zero/nil; slice fields REPLACE when non-nil and inherit when nil.
func mergeSession(top *MQTTConfig, s core.MQTTSession) *MQTTConfig {
	out := *top // shallow copy; slices are nil-safe because we replace/inherit below
	if s.ClientID != "" {
		out.ClientID = s.ClientID
	}
	if s.KeepAlive != nil {
		out.KeepAlive = s.KeepAlive
	}
	if s.CleanSession != nil {
		out.CleanSession = s.CleanSession
	}
	if s.Username != "" {
		out.Username = s.Username
	}
	if s.Password != "" {
		out.Password = s.Password
	}
	if s.Will != nil {
		out.Will = s.Will
	}
	if s.Subscriptions != nil {
		out.Subscriptions = s.Subscriptions
	}
	if s.Messages != nil {
		out.Messages = s.Messages
	}
	if s.PingAfterMessages != nil {
		// Bug fix: with *bool, a session can explicitly override
		// top-level true→false (previously impossible because the old
		// `if s.PingAfterMessages` only handled the true direction).
		out.PingAfterMessages = *s.PingAfterMessages
	}
	if s.Disconnect != nil {
		out.Disconnect = s.Disconnect
	}
	if s.DisconnectReason != nil {
		out.DisconnectReason = s.DisconnectReason
	}
	if s.Properties != nil {
		out.Properties = s.Properties
	}
	if s.ConnackProperties != nil {
		out.ConnackProperties = s.ConnackProperties
	}
	return &out
}

// emitSessionFlow emits one complete MQTT session: TCP 3-way handshake →
// CONNECT → CONNACK → [SUBSCRIBE/SUBACK] → [PUBLISH/ACK exchanges] →
// [PINGREQ/PINGRESP] → [DISCONNECT] → TCP 3-way teardown. sessionIdx is the
// index within Sessions[] (negative = single-session mode).
func emitSessionFlow(ctx context.Context, spec core.FlowSpec, cfg *MQTTConfig, sessionIdx int, configChan chan<- core.PacketConfig) error {
	if cfg == nil {
		return fmt.Errorf("mqtt: config is nil")
	}

	// Resolve the automatic client identifier once per flow so CONNECT encoding
	// is deterministic and concurrent tasks receive distinct identifiers.
	if cfg.ClientID == "" {
		resolved := *cfg
		resolved.ClientID = fmt.Sprintf("trafficgen-%06x", clientIDCounter.Add(1))
		// Empty ClientID forces CleanSession=true (3.1.1 §3.1.3.1: a
		// zero-byte ClientID is only allowed with CleanSession=1). The
		// builder forces this too, but it sees the *resolved* (non-empty)
		// ClientID, so the planner must force it here — otherwise an
		// explicit clean_session=false with empty client_id emits a
		// protocol-invalid CONNECT with flags bit1=0 (T-113/T-120).
		cs := true
		resolved.CleanSession = &cs
		cfg = &resolved
	}

	version := cfg.Version
	if version == 0 {
		version = 4
	}

	disconnect := true
	if cfg.Disconnect != nil {
		disconnect = *cfg.Disconnect
	}

	flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
	if sessionIdx >= 0 {
		flowID = fmt.Sprintf("%s:%s-%s-%d-%d:mqtt-%d", spec.SrcIP, spec.DstIP, flowID, spec.SrcPort, spec.DstPort, sessionIdx)
	}

	// Per-flow packet identifier auto-assignment (starts at 1; wraps from
	// 65535 back to 1, never 0).
	autoPacketID := uint16(1)

	// --- TCP state ---
	now := time.Now()
	packetIndex := uint64(0)
	ipID := uint16(0)
	nextIPID := func() uint16 {
		id := ipID
		ipID++
		return id
	}
	clientSeq := uint32(0)
	if spec.TCP != nil {
		clientSeq = spec.TCP.InitialSeq
	}
	if clientSeq == 0 {
		clientSeq = randUint32()
	}
	serverSeq := randUint32()
	winSize := uint16(65535)

	effectiveTTL := spec.TTL
	if effectiveTTL == 0 {
		effectiveTTL = DefaultTTL
	}
	mss := uint16(DefaultMSS)
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		mss = spec.TCP.MSS
	}
	synOpts := synOptions(mss)

	// emit (发送包) sends a TCP packet config to the channel.
	emit := func(direction string, seq, ack uint32, flags uint8, payload []byte) {
		if payload == nil {
			payload = []byte{}
		}
		// Direction swaps the on-wire src/dst: "down" (server→client)
		// emits from spec.DstIP:spec.DstPort to spec.SrcIP:spec.SrcPort.
		// Bug fix (T-038/T-039): previously L3/L4 were always built from
		// spec.SrcIP/SrcPort, so every packet in the pcap claimed the
		// client's address regardless of Direction — the direction field
		// was set but the bytes never followed it.
		srcIP, dstIP := spec.SrcIP, spec.DstIP
		srcPort, dstPort := spec.SrcPort, spec.DstPort
		if direction == "down" {
			srcIP, dstIP = dstIP, srcIP
			srcPort, dstPort = dstPort, srcPort
		}
		l3 := core.L3Base(srcIP, dstIP, 6, effectiveTTL, nextIPID(), spec)
		l4 := core.L4Config{
			Protocol:   "tcp",
			SrcPort:    srcPort,
			DstPort:    dstPort,
			Seq:        seq,
			Ack:        ack,
			Flags:      flags,
			WindowSize: winSize,
		}
		if flags == 0x02 || flags == 0x12 {
			l4.TCPOptions = synOpts
		}
		cfgOut := core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   direction,
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: core.EtherTypeFor(srcIP),
			},
			L3:       l3,
			L4:       l4,
			Payload:  payload,
			Metadata: groupIDMeta(spec),
		}
		if ctx != nil {
			select {
			case <-ctx.Done():
				return
			case configChan <- cfgOut:
			}
		} else {
			configChan <- cfgOut
		}
		packetIndex++
	}

	// emitData segments payload by MSS (MQTT control packets are NOT split —
	// only the TCP layer segments, per §2.1.4; the first segment carries the
	// MQTT fixed header, the rest are byte continuations).
	emitData := func(direction string, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
		for _, seg := range segmentByMSS(payload, int(mss)) {
			if ctx != nil {
				select {
				case <-ctx.Done():
					return senderSeq
				default:
				}
			}
			emit(direction, senderSeq, peerSeq, 0x18, seg)
			senderSeq += uint32(len(seg))
		}
		return senderSeq
	}

	// --- TCP handshake (TCP三次握手) ---
	emit("up", clientSeq, 0, 0x02, nil)
	clientSeq++
	emit("down", serverSeq, clientSeq, 0x12, nil)
	serverSeq++
	emit("up", clientSeq, serverSeq, 0x10, nil)

	// --- CONNECT (up) ---
	connectPkt := buildConnect(cfg)
	clientSeq = emitData("up", clientSeq, serverSeq, connectPkt)

	// --- CONNACK (down) ---
	connackPkt := buildConnack(cfg)
	serverSeq = emitData("down", serverSeq, clientSeq, connackPkt)

	// Per-flow packet identifier auto-assignment (starts at 1; wraps from
	// 65535 back to 1, never 0).
	nextID := func() uint16 {
		n := autoPacketID
		autoPacketID++
		if autoPacketID == 0 {
			autoPacketID = 1
		}
		return n
	}

	// If the CONNACK code != 0, the connection was rejected: skip all
	// subsequent MQTT packets and go straight to TCP teardown.
	if cfg.ConnectAckCode == 0 {
		// SUBSCRIBE / SUBACK.
		for _, sub := range cfg.Subscriptions {
			s := sub
			if s.PacketID == 0 {
				s.PacketID = nextID()
			}
			subscribePkt := buildSubscribe(s, version)
			clientSeq = emitData("up", clientSeq, serverSeq, subscribePkt)

			subackPkt := buildSuback(s.PacketID, s.AckReasonCodes, len(s.Filters), version)
			serverSeq = emitData("down", serverSeq, clientSeq, subackPkt)
		}

		// Messages: each PUBLISH followed by its QoS ack chain.
		for _, msg := range cfg.Messages {
			m := msg
			if m.PacketID == 0 && m.QoS > 0 {
				m.PacketID = nextID()
			}
			pkts := buildMessagePackets(version, m)
			for _, p := range pkts {
				dir := p.direction
				if dir == "" {
					dir = "up"
				}
				if dir == "down" {
					serverSeq = emitData("down", serverSeq, clientSeq, p.payload)
				} else {
					clientSeq = emitData("up", clientSeq, serverSeq, p.payload)
				}
			}
		}

		// PINGREQ / PINGRESP.
		if cfg.PingAfterMessages {
			clientSeq = emitData("up", clientSeq, serverSeq, buildPingreq())
			serverSeq = emitData("down", serverSeq, clientSeq, buildPingresp())
		}

		// Abnormal disconnect with a configured Will: model the broker-side
		// Will publication before connection teardown (design §4.4).
		if !disconnect && cfg.Will != nil {
			will := MQTTMessage{Topic: cfg.Will.Topic, Payload: cfg.Will.Payload, QoS: cfg.Will.QoS, Retain: cfg.Will.Retain, Direction: "down"}
			if will.QoS > 0 {
				will.PacketID = nextID()
			}
			for _, p := range buildMessagePackets(version, will) {
				if p.direction == "down" {
					serverSeq = emitData("down", serverSeq, clientSeq, p.payload)
				} else {
					clientSeq = emitData("up", clientSeq, serverSeq, p.payload)
				}
			}
		}

		// DISCONNECT (last MQTT packet). Skipped when the CONNACK code != 0
		// (connection rejected → TCP teardown follows directly).
		if disconnect {
			reason := 0
			if cfg.DisconnectReason != nil {
				reason = *cfg.DisconnectReason
			}
			clientSeq = emitData("up", clientSeq, serverSeq, buildDisconnect(version, reason))
		}
	}

	// --- TCP teardown (TCP三次挥手) ---
	// When TCP.RST=true, the planner emits a single RST instead of the
	// graceful FIN-based teardown.
	rst := spec.TCP != nil && spec.TCP.RST
	if rst {
		emit("up", clientSeq, serverSeq, 0x04, nil) // RST only (no ACK).
		return nil
	}
	emit("up", clientSeq, serverSeq, 0x11, nil)
	clientSeq++
	emit("down", serverSeq, clientSeq, 0x11, nil)
	serverSeq++
	emit("up", clientSeq, serverSeq, 0x10, nil)

	return nil
}

// messagePacket holds a payload and its direction.
type messagePacket struct {
	payload   []byte
	direction string
}

// buildMessagePackets builds the packet(s) for a single MQTT message.
func buildMessagePackets(version int, msg MQTTMessage) []messagePacket {
	var pkts []messagePacket
	dir := msg.Direction
	if dir == "" {
		dir = "up"
	}

	// Determine ack direction: opposite of publish direction.
	ackDir := "down"
	if dir == "down" {
		ackDir = "up"
	}

	// PUBLISH.
	pkts = append(pkts, messagePacket{payload: buildPublish(msg, version), direction: dir})

	// QoS 1: PUBACK (opposite direction).
	if msg.QoS == 1 {
		pkts = append(pkts, messagePacket{payload: buildPuback(msg.PacketID, version), direction: ackDir})
	}

	// QoS 2: PUBREC, PUBREL, PUBCOMP.
	if msg.QoS == 2 {
		pkts = append(pkts, messagePacket{payload: buildPubrec(msg.PacketID, version), direction: ackDir})
		pkts = append(pkts, messagePacket{payload: buildPubrel(msg.PacketID, version), direction: dir})
		pkts = append(pkts, messagePacket{payload: buildPubcomp(msg.PacketID, version), direction: ackDir})
	}

	return pkts
}

// randUint32 returns a pseudo-random 32-bit value for TCP sequence numbers
// (RFC 6528 ISN randomization). crypto/rand failure falls back to a simple
// time-based seed — determinism is not required for ISNs.
func randUint32() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err == nil {
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	return uint32(time.Now().UnixNano())
}

// synOptions builds the TCP SYN options (MSS + Window Scale + SACK-Permitted).
func synOptions(mss uint16) []core.TCPOption {
	return []core.TCPOption{
		{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}},
		{Kind: core.TCPOptWinScale, Data: []byte{7}},
		{Kind: core.TCPOptSACKPermit},
	}
}

// segmentByMSS splits payload into MSS-sized chunks. MQTT control packets
// are carried whole at the application layer — this function only segments
// the TCP stream (per MQTT 5.0 §2.1.4 the first chunk carries the fixed
// header; the receiver reassembles via Remaining Length).
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		mss = int(DefaultMSS)
	}
	if len(payload) <= mss {
		return [][]byte{payload}
	}
	var segs [][]byte
	for i := 0; i < len(payload); i += mss {
		end := i + mss
		if end > len(payload) {
			end = len(payload)
		}
		segs = append(segs, payload[i:end])
	}
	return segs
}

// groupIDMeta returns the group_id metadata when the spec has a GroupID
// strategy (keeps multi-session flows on the same PacketWorker — wire order
// = emit order). Mirrors the SOCKS5/RTSP convention.
func groupIDMeta(spec core.FlowSpec) map[string]interface{} {
	if spec.GroupID != nil && spec.GroupID.Strategy != "" {
		if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
			return map[string]interface{}{"group_id": g}
		}
	}
	return nil
}
