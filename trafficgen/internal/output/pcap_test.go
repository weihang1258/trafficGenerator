package output

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// readPCAPRecords parses a pcap file and returns the per-record timestamps
// (sec, usec) and captured lengths.
func readPCAPRecords(t *testing.T, path string) [][2]uint32 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	if len(data) < 24 {
		t.Fatalf("file too small for global header: %d", len(data))
	}
	if binary.LittleEndian.Uint32(data[0:4]) != 0xa1b2c3d4 {
		t.Fatalf("bad magic: %x", data[0:4])
	}
	var records [][2]uint32
	off := 24
	for off+16 <= len(data) {
		sec := binary.LittleEndian.Uint32(data[off : off+4])
		usec := binary.LittleEndian.Uint32(data[off+4 : off+8])
		caplen := binary.LittleEndian.Uint32(data[off+8 : off+12])
		records = append(records, [2]uint32{sec, usec})
		off += 16 + int(caplen)
	}
	return records
}

func TestPCAPWriter_Structure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	packets := [][]byte{
		make([]byte, 64),
		make([]byte, 128),
		make([]byte, 1500),
	}
	if err := w.Write(packets); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	records := readPCAPRecords(t, path)
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}
	want := []uint32{64, 128, 1500}
	// readPCAPRecords returns timestamps; re-read lengths for clarity
	data, _ := os.ReadFile(path)
	off := 24
	for i, w := range want {
		caplen := binary.LittleEndian.Uint32(data[off+8 : off+12])
		if caplen != w {
			t.Errorf("record %d caplen = %d, want %d", i, caplen, w)
		}
		off += 16 + int(caplen)
	}
}

// TestPCAPWriter_PerPacketTimestamp verifies that packets within a single
// Write() call get distinct timestamps (previously all shared one timestamp
// computed outside the loop). With a large batch, at least two records should
// differ in their microsecond timestamp.
func TestPCAPWriter_PerPacketTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ts.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	packets := make([][]byte, 500)
	for i := range packets {
		packets[i] = make([]byte, 64)
	}
	if err := w.Write(packets); err != nil {
		t.Fatalf("Write: %v", err)
	}
	w.Close()

	records := readPCAPRecords(t, path)
	seen := make(map[[2]uint32]bool)
	for _, r := range records {
		seen[r] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected per-packet timestamps to vary, but all %d records share one timestamp", len(records))
	}
}

// TestPCAPWriter_NoSyncPerWrite ensures Write does not fsync (which would make
// large writes slow). We can't observe fsync directly, but we can confirm a
// large write completes quickly when the file is not yet closed.
func TestPCAPWriter_NoSyncPerWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nosync.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	packets := make([][]byte, 2000)
	for i := range packets {
		packets[i] = make([]byte, 256)
	}
	start := time.Now()
	if err := w.Write(packets); err != nil {
		t.Fatalf("Write: %v", err)
	}
	elapsed := time.Since(start)
	w.Close()
	// 2000 small packets with per-call fsync would take >100ms on most disks.
	// Buffered writes should be well under that. Generous threshold to avoid
	// flakiness on slow CI disks.
	if elapsed > 500*time.Millisecond {
		t.Errorf("Write of 2000 small packets took %v, expected faster (no per-call fsync)", elapsed)
	}
}
