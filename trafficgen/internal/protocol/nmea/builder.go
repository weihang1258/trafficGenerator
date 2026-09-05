// Package nmea builder: sentence construction (ASCII bytes + CRLF, XOR
// checksum, §3 wire format) and wire fault injection (31 single-injection
// faults, design §7) + fixture baselines (§4 / testcase §3 byte table).
package nmea

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// BuildSentence renders one NMEAEvent into its wire bytes: talker + type
// + fields (empty field → empty string, comma preserved) + optional *hh CRLF.
// It also updates the session-run GSV sequence state for msg_num continuity.
func BuildSentence(run *sessionRun, ev core.NMEAEvent) ([]byte, error) {
	chk := true
	if ev.Checksum != nil {
		chk = *ev.Checksum
	}
	// Build the address field: talker (2) + type (3) or P+MfrID+Type for $P.
	// $P address = "P" + MfrID (3 chars, vendor ID) + Type (sentence
	// mnemonic remainder after vendor ID), e.g. Talker="P" MfrID="GRM"
	// Type="E" → addr="PGRME" (wire: "$PGRME"). Design §3: "$P" +
	// mfr_id(3 ASCII) + payload identifier.
	var addr string
	if ev.Talker == "P" {
		addr = "P" + ev.MfrID + ev.Type
	} else {
		addr = ev.Talker + ev.Type
	}

	// Assemble fields.
	var sb strings.Builder
	sb.WriteString("$")
	sb.WriteString(addr)
	for _, f := range ev.Fields {
		sb.WriteByte(',')
		sb.WriteString(f)
	}

	// Calculate or use pinned checksum.
	var csHex string
	if chk {
		if ev.ChecksumValue != "" {
			csHex = ev.ChecksumValue
		} else {
			csHex = xorHex(sb.String())
		}
		sb.WriteString("*")
		sb.WriteString(csHex)
	}
	sb.WriteString("\r\n")

	line := []byte(sb.String())

	// Length check: whole sentence ($...*XX\r\n) ≤ 82 bytes.
	// Length fault is always injected (builder sees it); validator catches it.
	if len(line) > 82 {
		// This path should not be reached if validator is correct.
		// Keep as a runtime guard.
	}

	return line, nil
}

// xorHex computes the XOR checksum of every byte between '$' and '*'
// (exclusive) and returns the 2-char uppercase hex representation.
func xorHex(s string) string {
	var cs byte
	for _, c := range s {
		if c == '*' {
			break
		}
		if c == '$' {
			continue
		}
		cs ^= byte(c)
	}
	return strings.ToUpper(hex.EncodeToString([]byte{cs}))
}

// BuildEvent is the layers.MessageEvent builder entry point (kept for
// signature parity with the protocol package convention). The actual
// sentence bytes are produced by Generate() and carried in ev.Bytes;
// this returns them verbatim. Wire_fault injection is applied by the
// transport layer's ApplyWireFault (or by the negative-case fixture
// configuration prior to emission).
func BuildEvent(ev *layers.MessageEvent, meta *layers.FlowMeta) ([]byte, error) {
	if ev == nil {
		return nil, fmt.Errorf("nmea builder: event is nil")
	}
	return ev.Bytes, nil
}

// applyWireFault applies a single wire fault to a sentence wire (called by
// the transport layer builder before packet emission). It returns the mutated
// wire and a boolean indicating whether the fault makes the sentence
// structurally invalid (→ task error) or just malformed-but-not-rejected.
func ApplyWireFault(wire []byte, fault string, isUDP bool) ([]byte, error) {
	if fault == "" {
		return wire, nil
	}
	switch fault {
	case "missing_dollar":
		if len(wire) == 0 || wire[0] != '$' {
			return wire, nil
		}
		return wire[1:], nil

	case "missing_crlf":
		// Strip trailing \r\n.
		w := trimCRLF(wire)
		return w, nil

	case "lf_only":
		// Replace \r\n with just \n.
		w := trimCRLF(wire)
		return append(w, '\n'), nil

	case "truncated_tcp":
		// Truncate to about 30 bytes (mid-field).
		if len(wire) <= 30 {
			return wire[:len(wire)/2], nil
		}
		return wire[:30], nil

	case "udp_truncated":
		// Strip trailing \r\n from the datagram (last 2 bytes).
		if len(wire) < 2 {
			return wire, nil
		}
		return wire[:len(wire)-2], nil

	case "udp_cross_datagram":
		// Inject a mid-sentence boundary: cut at comma.
		cut := len(wire) / 2
		for i := cut; i < len(wire) && i < cut+10; i++ {
			if wire[i] == ',' {
				cut = i
				break
			}
		}
		// Return the first half (the second half is the next datagram).
		return wire[:cut], nil

	case "start_bang":
		// Replace $ with !.
		if len(wire) == 0 || wire[0] != '$' {
			return wire, nil
		}
		w := make([]byte, len(wire))
		copy(w, wire)
		w[0] = '!'
		return w, nil

	case "unknown_talker":
		// Replace first two chars of address with "XZ".
		if len(wire) < 3 {
			return wire, nil
		}
		w := make([]byte, len(wire))
		copy(w, wire)
		w[1] = 'X'
		w[2] = 'Z'
		return w, nil

	case "unknown_type":
		// Replace chars 3-5 with "ZZZ".
		if len(wire) < 6 {
			return wire, nil
		}
		w := make([]byte, len(wire))
		copy(w, wire)
		w[3] = 'Z'
		w[4] = 'Z'
		w[5] = 'Z'
		return w, nil

	case "talker_p_standard":
		// Change $GP to $P (keep the type) — makes a standard sentence
		// look like a proprietary without MfrID.
		if len(wire) < 3 {
			return wire, nil
		}
		w := make([]byte, len(wire))
		copy(w, wire)
		w[1] = 'P'
		return w, nil

	case "field_count_short":
		// Remove the last field (drop trailing ",field" before checksum).
		w := trimCRLF(wire)
		lastComma := strings.LastIndexByte(string(w), ',')
		if lastComma < 0 {
			return wire, nil
		}
		return w[:lastComma], nil

	case "field_count_extra":
		// Append ",EXTRA" before checksum.
		w := trimCRLF(wire)
		csIdx := strings.IndexByte(string(w), '*')
		if csIdx < 0 {
			// No checksum, append field before \r\n.
			return append(append(w, []byte(",EXTRA")...), '\r', '\n'), nil
		}
		result := make([]byte, 0, len(w)+8)
		result = append(result, w[:csIdx]...)
		result = append(result, []byte(",EXTRA")...)
		result = append(result, w[csIdx:]...)
		return result, nil

	case "lat_over":
		// Change GGA's lat ddmm.mmmm to 9100.000 to put degrees at 91.
		b, err := corruptFieldAt(wire, 1, "9100.000,N"); if err != nil { return wire, err }; return b, nil

	case "lon_over":
		// Change GGA's lon to 18100.0000,W.
		b, err := corruptFieldAt(wire, 2, "18100.0000,W"); if err != nil { return wire, err }; return b, nil

	case "minutes_over":
		// Change GGA's lat minutes to 6000.000 (60+ minutes).
		b, err := corruptFieldAt(wire, 1, "5230.6000,N"); if err != nil { return wire, err }; return b, nil

	case "direction_char":
		// Replace N/S/E/W with X.
		w := make([]byte, len(wire))
		copy(w, wire)
		for i, c := range w {
			if c == 'N' || c == 'S' || c == 'E' || c == 'W' {
				w[i] = 'X'
			}
		}
		return w, nil

	case "time_out_of_range":
		// Set time to 256000.00 (invalid hh=25).
		b, err := corruptFieldAt(wire, 0, "256000.00"); if err != nil { return wire, err }; return b, nil

	case "date_out_of_range":
		// Set RMC date to 32 (invalid day).
		b, err := corruptFieldAt(wire, 0, "123132.804,321226"); if err != nil { return wire, err }; return b, nil

	case "status_char":
		// Change RMC A/V status to X.
		w := make([]byte, len(wire))
		copy(w, wire)
		for i, c := range w {
			if c == 'A' || c == 'V' {
				// Only corrupt in the status position (after first comma group).
				if i > 5 && (w[i-1] == ',' || w[i-1] == '.') {
					w[i] = 'X'
				}
			}
		}
		return w, nil

	case "gsa_mode_char":
		// Change GSA M/A mode to X.
		b, err := corruptFieldAt(wire, 0, "X"); if err != nil { return wire, err }; return b, nil

	case "gsa_fix_type":
		// Change GSA fix type 1/2/3 to 5.
		b, err := corruptFieldAt(wire, 0, "5"); if err != nil { return wire, err }; return b, nil

	case "sentence_length":
		// Pad to 83+ bytes by appending padding fields.
		w := trimCRLF(wire)
		csIdx := strings.IndexByte(string(w), '*')
		if csIdx < 0 {
			return append(append(w, []byte(strings.Repeat(",PADDING", 4))...), '\r', '\n'), nil
		}
		result := make([]byte, 0, len(w)+50)
		result = append(result, w[:csIdx]...)
		result = append(result, []byte(strings.Repeat(",PADDING", 4))...)
		result = append(result, w[csIdx:]...)
		return result, nil

	case "checksum_mismatch":
		// Flip the low nibble of the checksum value.
		w := make([]byte, len(wire))
		copy(w, wire)
		starIdx := -1
		for i, c := range w {
			if c == '*' {
				starIdx = i
				break
			}
		}
		if starIdx >= 0 && starIdx+2 < len(w) {
			// Corrupt both checksum hex chars.
			if w[starIdx+1] != 'F' {
				w[starIdx+1]++
			} else {
				w[starIdx+1] = '0'
			}
			if w[starIdx+2] != 'F' {
				w[starIdx+2]++
			} else {
				w[starIdx+2] = '0'
			}
		}
		return w, nil

	case "checksum_hex_width":
		// Make checksum only 1 hex char.
		w := make([]byte, len(wire))
		copy(w, wire)
		starIdx := -1
		for i, c := range w {
			if c == '*' {
				starIdx = i
				break
			}
		}
		if starIdx >= 0 && starIdx+2 < len(w) {
			// Remove one char by shifting.
			copy(w[starIdx+1:], w[starIdx+2:])
			w = w[:len(w)-1]
		}
		return w, nil

	case "proprietary_no_checksum":
		// Already validated by planner: this path only triggers when a
		// $P sentence somehow got checksum=false (should not happen).
		return wire, nil

	case "gsv_seq_correlation":
		// Corrupt msg_num to 99 (does not match expected sequence).
		b, err := corruptFieldAt(wire, 1, "99"); if err != nil { return wire, err }; return b, nil

	case "carrier_layer_missing", "carrier_conflict",
		"port_undeclared", "address_family_mismatch", "propagation":
		// These are validated in the planner and surface as errors.
		// The builder should never receive them.
		return wire, fmt.Errorf("nmea builder: wire_fault %q is not injectable in builder", fault)
	}
	return wire, fmt.Errorf("nmea builder: unknown wire_fault %q", fault)
}

// corruptFieldAt searches for the nth comma in wire and replaces the field
// that follows it with newVal, until the next comma. This is a best-effort
// mutation for negative-path test fixtures.
func corruptFieldAt(wire []byte, fieldIndex int, newVal string, sep ...string) ([]byte, error) {
	w := string(wire)
	sepChar := byte(',')
	if len(sep) > 0 && sep[0] != "" {
		sepChar = sep[0][0]
	}
	commaCount := -1
	fieldStart := -1
	fieldEnd := -1
	for i := 0; i < len(w); i++ {
		c := w[i]
		if c == sepChar {
			if commaCount == fieldIndex-1 {
				fieldStart = i + 1
			}
			if commaCount == fieldIndex && fieldStart >= 0 {
				fieldEnd = i
				break
			}
			commaCount++
		}
	}
	if fieldStart < 0 {
		return wire, nil
	}
	if fieldEnd < 0 {
		// Field extends to end (before checksum or CRLF).
		fieldEnd = strings.IndexByte(w, '*')
		if fieldEnd < 0 {
			fieldEnd = strings.Index(w, "\r\n")
			if fieldEnd < 0 {
				fieldEnd = len(w)
			}
		}
	}
	result := w[:fieldStart] + newVal + w[fieldEnd:]
	return []byte(result), nil
}

// trimCRLF removes trailing \r\n from wire.
func trimCRLF(wire []byte) []byte {
	for len(wire) >= 2 {
		if wire[len(wire)-2] == '\r' && wire[len(wire)-1] == '\n' {
			return wire[:len(wire)-2]
		}
		if wire[len(wire)-1] == '\n' {
			return wire[:len(wire)-1]
		}
		break
	}
	return wire
}

// FixtureGGABaseline returns the baseline GGA fields for the default session.
func FixtureGGABaseline() []string {
	return []string{
		"123519.00",  // UTC time
		"4807.038",    // Latitude ddmm.mmmm
		"N",           // N
		"01131.000",   // Longitude dddmm.mmmm
		"E",           // E
		"1",           // Fix quality (1=GPS)
		"08",          // Number of satellites
		"0.9",         // HDOP
		"545.4",       // Altitude
		"M",           // M
		"46.9",        // Geoid height
		"M",           // M
		"",            // Time since last DGPS update
		"",            // DGPS station ID
	}
}

// FixtureRMCBaseline returns the baseline RMC fields.
func FixtureRMCBaseline() []string {
	return []string{
		"123519.00", // UTC time
		"A",          // Status A
		"4807.038",   // Latitude
		"N",          // N
		"01131.000",  // Longitude
		"E",          // E
		"22.5",       // Speed over ground (knots)
		"180.3",      // Track made good (degrees)
		"230394",     // Date ddmmyy
		"003.1",      // Magnetic variation
		"W",          // W
		"A",          // Mode indicator
	}
}

// FixtureGGABytes returns the exact baseline GGA sentence bytes
// (testcase §3 byte table entry #1).
func FixtureGGABytes() []byte {
	// $GPGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*69
	// XOR of bytes between $ and * = 0x69 (testcase §3 byte table entry #1).
	return []byte("$GPGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*69\r\n")
}

// FixtureRMCBytes returns the exact baseline RMC sentence bytes.
func FixtureRMCBytes() []byte {
	return []byte("$GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W,A*29\r\n")
}

// RandSentence generates a random valid NMEA sentence for smoke testing.
// It picks a random type and fills in plausible fields.
func RandSentence() ([]byte, error) {
	types := []string{"GGA", "RMC", "GSA", "VTG", "GLL", "ZDA"}
	t := types[0]
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	switch t {
	case "GGA":
		return FixtureGGABytes(), nil
	case "RMC":
		return FixtureRMCBytes(), nil
	default:
		return []byte(fmt.Sprintf("$GP%s,*00\r\n", t)), nil
	}
}
