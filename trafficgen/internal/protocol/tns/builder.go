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
	payload, err := bodyForType(pt, ev)
	if err != nil {
		return nil, err
	}
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

// bodyForType builds a parseable TNS body for a packet type. CONNECT/ACCEPT use
// a minimal valid connect_common structure (design §3.1/§3.2 requires a
// parseable body, never the ASCII profile name on the wire); REFUSE/REDIRECT
// use a minimal footer; DATA carries 2-byte data_flags (added by buildPacket)
// plus optional opaque payload. The design v1 does not fabricate Oracle
// version-specific negotiation bytes, so the bodies carry only the fixed
// structural fields needed for tshark to dissect without a [Malformed Packet].
func bodyForType(pt byte, ev core.TNSEvent) ([]byte, error) {
	switch pt {
	case TypeConnect:
		return connectBody(), nil
	case TypeAccept:
		return acceptBody(), nil
	case TypeRefuse:
		return refuseBody(), nil
	case TypeRedirect:
		return redirectBody(), nil
	case TypeData:
		return nil, nil
	default:
		// Unknown type is rejected earlier by eventType; defensive.
		return nil, fmt.Errorf("tns: bodyForType unsupported type %#x", pt)
	}
}

// connectCommonVOO is the fixed connect_common prefix shared by CONNECT and
// ACCEPT: version(2)+compat(2)+service_options(2) + sdu(2)+max_tdu(2) +
// nt_proto(2)+line_turnaround(2) + value_of_one(2). These are the structural
// bytes Wireshark reads before the variable length/offset fields.
func connectCommonVOO() []byte {
	b := make([]byte, 0, 16)
	b = appendU16(b, 0x0136) // version
	b = appendU16(b, 0x0136) // compat_version
	b = appendU16(b, 0x0821) // service_options
	b = appendU16(b, 0x2000) // sdu_size
	b = appendU16(b, 0x2000) // max_tdu_size
	b = appendU16(b, 0x0300) // nt_proto_characteristics
	b = appendU16(b, 0x0000) // line_turnaround
	b = appendU16(b, 0x4001) // value_of_one
	return b
}

// connectBody builds a minimal CONNECT body: connect_common prefix + connect
// data length/offset/max + flags + trace fields + connect_data. The connect
// data is a benign TNSPING-style descriptor string (profile name is NOT used).
func connectBody() []byte {
	b := connectCommonVOO()
	cd := []byte("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=test)))")
	b = appendU16(b, uint16(len(cd))) // connect_data_length
	b = appendU16(b, 0)               // connect_data_offset
	b = appendU16(b, uint16(len(cd))) // connect_data_max
	b = appendU16(b, 0)               // flags0
	b = appendU16(b, 0)               // flags1
	b = appendU64(b, 0)               // trace_cf1
	b = appendU64(b, 0)               // trace_cf2
	b = appendU64(b, 0)               // trace_cid
	return append(b, cd...)
}

// acceptBody builds a minimal ACCEPT body: connect_common prefix + accept data
// length/offset (empty accept data). ACCEPT uses nt_proto_characteristics
// 0x0736 (the accept variant), distinct from CONNECT's 0x0300.
func acceptBody() []byte {
	b := connectCommonVOO()
	b[10] = 0x07 // nt_proto_characteristics for ACCEPT
	b[11] = 0x36
	b = appendU16(b, 0) // accept_data_length
	b = appendU16(b, 0) // accept_data_offset
	return b
}

// refuseBody builds a minimal REFUSE body: reason user/system + refuse data
// length + refuse data (empty), padded to tshark's expected layout.
func refuseBody() []byte {
	b := []byte{0, 0}    // refuse_reason_user, refuse_reason_system
	b = appendU16(b, 0)  // refuse_data_length
	b = appendU16(b, 0)  // refuse_data (empty -> pad)
	b = appendU16(b, 0)  // trailing pad to satisfy the fixed footer
	return b
}

// redirectBody builds a minimal REDIRECT body: redirect_data_length(2)=0 plus
// 2-byte pad so Wireshark reads the fixed footer without overrunning.
func redirectBody() []byte {
	return []byte{0, 0, 0, 0} // redirect_data_length(2)=0 + pad(2)
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

// appendU16 appends a big-endian uint16.
func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// appendU64 appends a big-endian uint64.
func appendU64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
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
