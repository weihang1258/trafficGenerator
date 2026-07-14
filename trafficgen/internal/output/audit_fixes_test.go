package output

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAuditFix_PcapTimestampUsesScheduled (H5): PCAPWriter.WriteTimed writes
// the caller-provided Timestamp into the pcap record, not time.Now().
//
// Before the fix, the Write path used time.Now() unconditionally, so replayed
// pcaps had wall-clock write timestamps instead of the scheduled send times --
// destroying the replay's temporal fidelity.
//
// This test writes THREE packets with distinct known timestamps and reads the
// raw pcap bytes back, asserting each record's seconds field matches exactly.
// The multi-packet form catches a regression that honors packet[0]'s timestamp
// but falls back to time.Now() for packets [1..N].
func TestAuditFix_PcapTimestampUsesScheduled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	// Three distinct, recognizable, non-current timestamps.
	scheduled := []time.Time{
		time.Date(2000, 1, 1, 0, 0, 42, 123000, time.UTC),
		time.Date(2001, 6, 15, 12, 34, 56, 789000, time.UTC),
		time.Date(2005, 12, 31, 23, 59, 59, 999000, time.UTC),
	}
	packets := make([]TimedPacket, len(scheduled))
	for i, ts := range scheduled {
		packets[i] = TimedPacket{Data: []byte{byte(i), byte(i), byte(i), byte(i), byte(i)}, Timestamp: ts}
	}
	if err := w.WriteTimed(packets); err != nil {
		t.Fatalf("WriteTimed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Global header: 24B. Each record: 16B header + 5B payload = 21B.
	if len(b) < 24+3*21 {
		t.Fatalf("pcap file too short: %d bytes", len(b))
	}
	for i, ts := range scheduled {
		recOffset := 24 + i*21
		secs := binary.LittleEndian.Uint32(b[recOffset : recOffset+4])
		usecs := binary.LittleEndian.Uint32(b[recOffset+4 : recOffset+8])
		wantSecs := uint32(ts.Unix())
		wantUsecs := uint32(ts.Nanosecond() / 1000)
		if secs != wantSecs {
			t.Errorf("packet %d: pcap record seconds = %d, want %d (scheduled=%v). H5 regression: not using scheduled Timestamp per-packet", i, secs, wantSecs, ts)
		}
		if usecs != wantUsecs {
			t.Errorf("packet %d: pcap record microseconds = %d, want %d", i, usecs, wantUsecs)
		}
		// Sanity: no value should look like time.Now().
		if int64(secs) > time.Now().Unix()-1000000 {
			t.Errorf("packet %d: seconds looks like time.Now() (%d), want scheduled %d", i, secs, wantSecs)
		}
	}
}

// TestAuditFix_PcapTimestampZeroFallback (H5 boundary): if Timestamp is zero,
// WriteTimed falls back to time.Now() (documented behavior). This test guards
// against a fix that breaks the zero-value fallback.
func TestAuditFix_PcapTimestampZeroFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-zero.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	before := time.Now().Unix()
	err = w.WriteTimed([]TimedPacket{
		{Data: []byte("hi"), Timestamp: time.Time{}}, // zero -> fallback to now
	})
	if err != nil {
		t.Fatalf("WriteTimed: %v", err)
	}
	after := time.Now().Unix()
	w.Close()
	b, _ := os.ReadFile(path)
	secs := binary.LittleEndian.Uint32(b[24:28])
	if int64(secs) < before || int64(secs) > after+1 {
		t.Errorf("zero-timestamp fallback: got %d, expected in [%d, %d]", secs, before, after)
	}
}
