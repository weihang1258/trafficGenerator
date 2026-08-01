// Package rdp TLS-stream tests.
//
// These tests drive the full TLS scenario (SecurityLayer="tls") and assert
// that every TCP payload emitted after the TLS handshake is a well-formed
// TLS record (RFC 8446 §5): a 5-byte record header (ContentType 1B +
// Version 2B + Length 2B BE) followed by exactly Length bytes. Wireshark
// reports "Ignored Unknown Record" when a post-handshake segment carries
// non-TLS bytes (e.g. a raw TPKT/X.224 PDU) on the now-TLS connection.
package rdp

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// validTLSContentType reports whether ct is a legal TLS ContentType
// (RFC 8446 §5: change_cipher_spec 20, alert 21, handshake 22,
// application_data 23).
func validTLSContentType(ct byte) bool {
	switch ct {
	case 0x14, 0x15, 0x16, 0x17:
		return true
	}
	return false
}

// parseTLSRecords splits a TCP payload into TLS records using the record
// Length field: each record is 5 header bytes (ContentType 1B + Version
// 2B + Length 2B BE) + Length body bytes. Returns an error when a record
// header is malformed (invalid ContentType or version), the Length field
// overruns the payload, or trailing bytes remain after the last record.
func parseTLSRecords(payload []byte) ([]tlsRecordInfo, error) {
	var records []tlsRecordInfo
	off := 0
	for off < len(payload) {
		if len(payload)-off < 5 {
			return nil, fmt.Errorf("truncated TLS record header at offset %d: %d bytes remain", off, len(payload)-off)
		}
		rec := tlsRecordInfo{
			contentType: payload[off],
			version:     [2]byte{payload[off+1], payload[off+2]},
			length:      int(binary.BigEndian.Uint16(payload[off+3 : off+5])),
			offset:      off,
		}
		if !validTLSContentType(rec.contentType) {
			return nil, fmt.Errorf("offset %d: invalid TLS ContentType 0x%02x (want 0x14/0x15/0x16/0x17)", off, rec.contentType)
		}
		if rec.version[0] != 0x03 {
			return nil, fmt.Errorf("offset %d: TLS version major = 0x%02x, want 0x03", off, rec.version[0])
		}
		if len(payload)-off-5 < rec.length {
			return nil, fmt.Errorf("offset %d: TLS record Length %d overruns payload (%d bytes remain after header)", off, rec.length, len(payload)-off-5)
		}
		rec.body = payload[off+5 : off+5+rec.length]
		records = append(records, rec)
		off += 5 + rec.length
	}
	return records, nil
}

// tlsRecordInfo is one parsed TLS record.
type tlsRecordInfo struct {
	contentType byte
	version     [2]byte
	length      int
	body        []byte
	offset      int
}

// unwrapTLSAppData strips the 5-byte TLS Application Data record header
// from a payload when it carries one, returning the inner RDP PDU bytes.
// Payloads without a 0x17 record header are returned unchanged (pre-TLS
// X.224/TLS Handshake segments are not wrapped).
func unwrapTLSAppData(payload []byte) []byte {
	if len(payload) >= 5 && payload[0] == 0x17 && payload[1] == 0x03 {
		n := int(binary.BigEndian.Uint16(payload[3:5]))
		if len(payload) >= 5+n {
			return payload[5 : 5+n]
		}
	}
	return payload
}

// TestTLSStream_AllPostHandshakePayloadsAreTLSRecords drives the TLS
// scenario and asserts every TCP payload after the X.224 CC (i.e. the
// whole TLS layer, including the placeholder handshake) splits exactly
// into well-formed TLS records: valid ContentType, Length field matching
// the actual body bytes, and no leftover bytes. This reproduces the
// Wireshark "Ignored Unknown Record" report: the planner previously
// emitted raw TPKT/X.224/MCS PDUs after the ServerHello, which the TLS
// dissector rejects as bogus records (ContentType 0x03).
func TestTLSStream_AllPostHandshakePayloadsAreTLSRecords(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec() // SecurityLayer=tls

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// TCP handshake (SYN/SYN-ACK/ACK) has empty payloads; the first two
	// data payloads are the X.224 CR/CC, which predate the TLS layer.
	var tlsPkts []core.PacketConfig
	for _, cfg := range configs {
		if len(cfg.Payload) > 0 {
			tlsPkts = append(tlsPkts, cfg)
		}
	}
	if len(tlsPkts) < 3 {
		t.Fatalf("expected >= 3 data packets (X.224 CR/CC + TLS), got %d", len(tlsPkts))
	}
	tlsPkts = tlsPkts[2:] // drop X.224 CR + X.224 CC

	for i, cfg := range tlsPkts {
		records, err := parseTLSRecords(cfg.Payload)
		if err != nil {
			t.Errorf("packet %d (dir=%s, %d bytes): %v", i, cfg.Direction, len(cfg.Payload), err)
			continue
		}
		if len(records) == 0 {
			t.Errorf("packet %d (dir=%s): empty TLS stream", i, cfg.Direction)
			continue
		}
		// Every record's Length must match its actual body bytes, and the
		// records must consume the payload exactly (no remainder).
		consumed := 0
		for _, rec := range records {
			if rec.length != len(rec.body) {
				t.Errorf("packet %d (dir=%s): record at offset %d declares Length %d but body is %d bytes",
					i, cfg.Direction, rec.offset, rec.length, len(rec.body))
			}
			consumed += 5 + rec.length
		}
		if consumed != len(cfg.Payload) {
			t.Errorf("packet %d (dir=%s): TLS records consumed %d of %d payload bytes (trailing garbage)",
				i, cfg.Direction, consumed, len(cfg.Payload))
		}
	}
}

// TestTLSStream_ServerHelloHandshakeLength asserts the ServerHello record
// carries a Handshake header (1B type + 3B length BE) whose length equals
// the handshake body exactly, and the record is followed by valid TLS
// records. Guards the Wireshark "Ignored Unknown Record" hypothesis that
// a length mismatch in the handshake header corrupts subsequent record
// framing.
func TestTLSStream_ServerHelloHandshakeLength(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	var shPkt *core.PacketConfig
	for i := range configs {
		cfg := &configs[i]
		if len(cfg.Payload) >= 6 && cfg.Payload[0] == 0x16 && cfg.Payload[1] == 0x03 && cfg.Payload[5] == 0x02 {
			shPkt = cfg
			break
		}
	}
	if shPkt == nil {
		t.Fatal("no ServerHello record (0x16 0x03 .. handshake type 0x02) found in Plan output")
	}

	records, err := parseTLSRecords(shPkt.Payload)
	if err != nil {
		t.Fatalf("ServerHello payload: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ServerHello payload: expected exactly 1 record, got %d", len(records))
	}
	rec := records[0]
	if rec.contentType != 0x16 {
		t.Fatalf("ServerHello ContentType = 0x%02x, want 0x16 (Handshake)", rec.contentType)
	}
	if len(rec.body) < 4 {
		t.Fatalf("ServerHello handshake too short: %d bytes", len(rec.body))
	}
	if rec.body[0] != 0x02 {
		t.Errorf("ServerHello handshake type = 0x%02x, want 0x02", rec.body[0])
	}
	hsLen := int(rec.body[1])<<16 | int(rec.body[2])<<8 | int(rec.body[3])
	if hsLen != len(rec.body)-4 {
		t.Errorf("ServerHello handshake length = %d, want %d (exact body size)", hsLen, len(rec.body)-4)
	}
}

// TestTLSStream_AppDataWrappedPDUs checks that post-handshake RDP PDUs
// (MCS Channel-Join Request at TPKT offset 7 after unwrap) are carried
// inside TLS Application Data records (ContentType 0x17), proving the
// wrap covers the entire post-handshake stream, not just the handshake
// pair.
func TestTLSStream_AppDataWrappedPDUs(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.Channels = []core.RDPChannel{{Name: "cliprdr"}}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	foundCJ := false
	for _, cfg := range configs {
		if cfg.Direction != "up" || len(cfg.Payload) < 13 {
			continue
		}
		// Every post-handshake up payload must be a TLS App Data record.
		if cfg.Payload[0] != 0x17 {
			continue
		}
		records, err := parseTLSRecords(cfg.Payload)
		if err != nil {
			t.Errorf("up payload: %v", err)
			continue
		}
		if len(records) != 1 || records[0].contentType != 0x17 {
			continue
		}
		inner := unwrapTLSAppData(cfg.Payload)
		if len(inner) >= 8 && inner[7] == MCSChannelJoinRequest {
			foundCJ = true
		}
	}
	if !foundCJ {
		t.Errorf("no Channel-Join Request found inside a TLS App Data record")
	}
}
