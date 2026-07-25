package core

import "unicode/utf8"

// IsText reports whether b is a safe text payload: valid UTF-8 with no NUL
// bytes. Used by protocol planners (FTP, SIP, SCTP, HTTP, ICMP) to choose
// between carrying resolved []byte from a PayloadCache through a string
// field (e.g. SubFlowSpec.Payload, HTTPConfig.Body) and carrying it
// through the base64-encoded binary-safe alternative
// (SubFlowSpec.PayloadB64, HTTPConfig.BodyB64, ...).
//
// The heuristic is intentionally conservative on two fronts:
//
//  1. NUL bytes force the binary path. encoding/json marshals a string
//     with a NUL byte into " ", which round-trips correctly through
//     json.Unmarshal, but downstream PCAP writers and many DPI engines
//     treat a NUL as a C-string terminator and truncate the payload
//     silently. Routing NUL-bearing bytes through the *B64 field avoids
//     the JSON string path entirely.
//
//  2. Invalid UTF-8 forces the binary path. encoding/json rejects invalid
//     UTF-8 in string fields at marshal time (the JSON spec mandates
//     UTF-8), so a string field carrying invalid UTF-8 would fail the
//     entire marshal. Routing through *B64 sidesteps the issue.
//
// Anything else (ASCII, valid UTF-8 without NUL) takes the text path,
// keeping JSON marshalling readable and the on-disk debug representation
// of the SubFlowSpec / *Config usable.
//
// Mirrors the prior ftp.isText helper (Task 11) and moved to core in
// Task 12 so all five planners share one definition instead of five
// copies of the same six-line heuristic.
func IsText(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return utf8.Valid(b)
}
