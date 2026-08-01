package dhcpv6

// Regression tests for OPTION_RDNSS (23) / OPTION_DNSSL (24) wire format.
//
// Found via Wireshark pcap verification (2026-08-01): the builders
// prepended a 4-byte "lifetime" to the option data, but RFC 3646 (DNS
// Configuration options for DHCPv6) defines NO lifetime field for either
// option — the data is the address list / domain list directly:
//
//   OPTION_DNS_RECURSIVE_NAME_SERVER (23):
//     option-len = 16 * (number of addresses); data = IPv6 addresses
//   OPTION_DNSSL (24):
//     option-len = total encoded length; data = RFC 3315 §8.14 domain names
//
// (RFC 6106 — the ICMPv6 RA variant — DOES carry a lifetime; the two
// were conflated.) Wireshark rejects the extra 4 bytes: option 23 with
// length 20 % 16 != 0 is "DNS servers address: malformed option", and
// option 24 starting with 0x00 (the lifetime high byte) parses as a
// root-only domain ".". These tests pin the exact on-wire bytes per
// RFC 3646.

import (
	"bytes"
	"testing"
)

// TestBuildRDNSS_NoLifetimeField: RFC 3646 §3 — option 23 data is the
// IPv6 address list only (16 bytes per server), no 32-bit lifetime
// prefix. FAILS before the fix: the builder prepends 4 bytes
// (0x00000e10 = 3600), making the data 20 bytes and the option
// malformed in Wireshark.
func TestBuildRDNSS_NoLifetimeField(t *testing.T) {
	got := BuildRDNSS([]string{"2001:db8::53"})
	want := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("BuildRDNSS = %x, want %x (16 bytes, no lifetime)", got, want)
	}
	if len(got)%16 != 0 {
		t.Errorf("BuildRDNSS length %d not a multiple of 16 — Wireshark reports malformed option", len(got))
	}
}

// TestBuildDNSSL_NoLifetimeField: RFC 3646 §2 — option 24 data is the
// domain list only (RFC 3315 §8.14 wire format), no 32-bit lifetime
// prefix. FAILS before the fix: the builder prepends 4 bytes, so the
// first data byte is 0x00 which Wireshark parses as a root-only domain
// ".".
func TestBuildDNSSL_NoLifetimeField(t *testing.T) {
	got := BuildDNSSL([]string{"example.com"})
	// "example.com" wire: 07 'example' 03 'com' 00 = 13 bytes.
	want := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("BuildDNSSL = %x, want %x (13 bytes, no lifetime)", got, want)
	}
	if got[0] == 0x00 {
		t.Errorf("BuildDNSSL first byte is 0x00 — Wireshark parses a root-only domain")
	}
}

// TestBuildRDNSS_MultiServer: two servers → 32 bytes of addresses.
func TestBuildRDNSS_MultiServer(t *testing.T) {
	got := BuildRDNSS([]string{"2001:db8::53", "2001:db8::54"})
	if len(got) != 32 {
		t.Fatalf("BuildRDNSS 2 servers = %d bytes, want 32 (16 each)", len(got))
	}
	if !bytes.Equal(got[16:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x54}) {
		t.Errorf("second server bytes = %x, want 2001:db8::54", got[16:])
	}
}
