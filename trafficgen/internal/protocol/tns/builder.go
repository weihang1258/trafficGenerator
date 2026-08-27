package tns

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TNS packet type constants.
const (
	TypeConnect  = 0x01
	TypeAccept   = 0x02
	TypeRefuse   = 0x04
	TypeRedirect = 0x05
	TypeData     = 0x06
)

// maxLength is the largest length encodable in the 16-bit TNS length field
// (§2.1: 8 <= length <= 65535, checked before writing U16).
const maxLength = 0xffff

// typeCode maps a config type string to a TNS packet type byte.
func typeCode(s string) (byte, bool) {
	switch s {
	case "CONNECT":
		return TypeConnect, true
	case "ACCEPT":
		return TypeAccept, true
	case "REFUSE":
		return TypeRefuse, true
	case "REDIRECT":
		return TypeRedirect, true
	case "DATA":
		return TypeData, true
	}
	return 0, false
}

// buildHeader builds an 8-byte TNS header.
// length: total packet length (header + body), min 8.
// packetType: one of the Type* constants.
// checksum: 0x0000 for disabled mode.
func buildHeader(length uint16, packetType byte, checksum uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], length)
	binary.BigEndian.PutUint16(b[2:4], checksum)
	b[4] = packetType
	b[5] = 0x00                                  // reserved
	binary.BigEndian.PutUint16(b[6:8], checksum) // header_checksum
	return b
}

// buildPacket assembles one TNS packet from a config event.
// Non-DATA packets: header(8) + payload. DATA packets: header(8) + data_flags(2) + payload.
func buildPacket(ev core.TNSEvent) ([]byte, error) {
	pt, err := eventType(ev)
	if err != nil {
		return nil, err
	}
	payload := profilePayload(ev.PayloadProfile)
	if pt == TypeData {
		if ev.DataFlags != 0 {
			return nil, fmt.Errorf("tns: DATA data_flags must be 0 (got %d)", ev.DataFlags)
		}
		totalLen := 8 + 2 + len(payload)
		return buildDataPacket(uint16(totalLen), 0, payload), nil
	}
	totalLen := 8 + len(payload)
	hdr := buildHeader(uint16(totalLen), pt, 0)
	pkt := make([]byte, 0, len(hdr)+len(payload))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, payload...)
	return pkt, nil
}

// eventType resolves the type byte for an event, accepting string or numeric
// config. Only the five valid TNS packet types are accepted in either form;
// any other numeric value (e.g. 127 in a negative test) is rejected so the
// error surfaces as an unknown-type error.
func eventType(ev core.TNSEvent) (byte, error) {
	switch t := ev.Type.(type) {
	case string:
		pt, ok := typeCode(t)
		if !ok {
			return 0, fmt.Errorf("tns: unknown packet type %q", t)
		}
		return pt, nil
	case float64:
		return validNumericType(int32(t))
	case int:
		return validNumericType(int32(t))
	case int32:
		return validNumericType(t)
	case uint32:
		return validNumericType(int32(t))
	default:
		return 0, fmt.Errorf("tns: unknown packet type %v", ev.Type)
	}
}

// validNumericType accepts a numeric packet type only if it is one of the five
// defined types. A v1 config may not emit RAW types; 127 must fail validation.
func validNumericType(t int32) (byte, error) {
	switch t {
	case TypeConnect, TypeAccept, TypeRefuse, TypeRedirect, TypeData:
		return byte(t), nil
	default:
		return 0, fmt.Errorf("tns: unknown packet type %d", t)
	}
}

// buildDataPacket builds a DATA TNS packet: header + 2-byte data_flags + payload.
func buildDataPacket(length uint16, dataFlags uint16, payload []byte) []byte {
	hdr := buildHeader(length, TypeData, 0)
	df := make([]byte, 2)
	binary.BigEndian.PutUint16(df, dataFlags)
	pkt := make([]byte, 0, len(hdr)+2+len(payload))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, df...)
	pkt = append(pkt, payload...)
	return pkt
}

// profilePayload returns a minimal non-empty placeholder payload for a given profile name.
// The payload is a contract name, not real Oracle wire bytes — it just needs to be
// non-empty so the packet has a valid length > 8. The design v1 explicitly does not
// fabricate Oracle version-specific bytes.
func profilePayload(profile string) []byte {
	if profile == "" {
		profile = "tns"
	}
	return []byte(profile)
}

// wireFault is the negative-test fault injection: planner checks it before
// constructing any packet, returning a config error.
type wireFault struct {
	Kind  string      `json:"kind"`
	Value interface{} `json:"value"`
}

// checkWireFault parses the config wire_fault and returns a config error if the
// injected fault is in scope for this build.
func checkWireFault(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var f wireFault
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("tns: invalid wire_fault: %v", err)
	}
	switch f.Kind {
	case "length":
		return fmt.Errorf("tns: wire fault: packet length %v below minimum 8", f.Value)
	case "packet_checksum":
		return fmt.Errorf("tns: wire fault: packet_checksum %v conflicts with disabled checksum mode", f.Value)
	case "data_flags":
		return fmt.Errorf("tns: wire fault: nonzero data_flags %v rejected in v1", f.Value)
	default:
		return fmt.Errorf("tns: wire fault: unknown kind %q", f.Kind)
	}
}
