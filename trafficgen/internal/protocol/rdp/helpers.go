// Package rdp implements the RDP (Remote Desktop Protocol) planner.
// This file provides small helper utilities that require external
// packages (encoding/base64). Keeping these separate from planner.go
// lets the main planner file stay focused on protocol encoding.
package rdp

import "encoding/base64"

func init() {
	// Wire the base64 decoder to the real encoding/base64 implementation.
	base64StdDecodeString = func(s string) ([]byte, error) {
		return base64.StdEncoding.DecodeString(s)
	}
}
