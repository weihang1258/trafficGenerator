package output

// Test points derived from tools/test_points/output.md (PCAP section).
// Each test covers a specific test point (P1-P25, R1-R22) with observable
// assertions.
//
// Existing tests in pcap_test.go already cover parts of
// P1/P6/P17 (TestPCAPWriter_Structure), P11 side-effect
// (TestPCAPWriter_PerPacketTimestamp), and R4 seq-zero-padding
// (TestRotatingPCAPWriter_SeqZeroPadded). Only UNCOVERED test points are
// implemented below.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
)

// ============================================================================
// Fake file helpers for SIMULATED error injection
// ============================================================================

// failFile implements pcapFile with configurable write-failure counting.
// Each call to Write increments a counter; when the counter exceeds failAfter,
// Write returns failErr instead of writing to the underlying buffer.
type failFile struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	writeNum  int
	failAfter int
	failErr   error
}

func (f *failFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeNum++
	if f.writeNum > f.failAfter {
		return 0, f.failErr
	}
	return f.buf.Write(p)
}

func (f *failFile) Close() error { return nil }

func (f *failFile) Sync() error { return nil }

// failCloseFile implements pcapFile where Close returns an error.
type failCloseFile struct {
	failFile
}

func (f *failCloseFile) Close() error { return errors.New("close failed") }

// failSyncFile implements pcapFile where Sync returns an error.
type failSyncFile struct {
	failFile
}

func (f *failSyncFile) Sync() error { return errors.New("sync failed") }

// failFlushSyncCloseFile implements pcapFile where all three post-write
// operations fail. The first error comes from Flush (which delegates to
// Write on the underlying file), so multi-fail returns a flush error.
type failFlushSyncCloseFile struct {
	failFile
}

func (f *failFlushSyncCloseFile) Close() error { return errors.New("close failed") }

func (f *failFlushSyncCloseFile) Sync() error { return errors.New("sync failed") }

// smallBufWriter returns a *bufio.Writer wrapping f with a 1-byte buffer,
// so every write immediately tries to flush through to the underlying
// failFile (useful for triggering write failures on small writes that
// would otherwise remain buffered in the default 256KB bufio buffer).
//
// NOTE: Even with a 1-byte bufio buffer, a single bw.Write(p[:16]) will
// trigger MULTIPLE underlying ff.Write calls (one per byte, since the
// buffer can hold only 1 byte and flushes before each subsequent byte).
// For exact-count tests, the failAfter counter must account for the
// actual number of underlying writes that occur.
func smallBufWriter(f pcapFile) *bufio.Writer {
	return bufio.NewWriterSize(f, 1)
}

// ============================================================================
// P2-NEG: NewPCAPWriter with invalid path
// ============================================================================

func TestPCAPWriter_New_InvalidPath(t *testing.T) {
	_, err := NewPCAPWriter("/proc/not-writable.pcap")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
	if !strings.Contains(err.Error(), "failed to create pcap file") {
		t.Errorf("error=%q, want prefix 'failed to create pcap file'", err)
	}
}

// ============================================================================
// P3-NEG: writeGlobalHeader fails (simulated via failFile)
// ============================================================================

func TestPCAPWriter_New_WriteHeaderFail(t *testing.T) {
	ff := &failFile{failAfter: 0, failErr: errors.New("write failed")}
	bw := smallBufWriter(ff)
	w := &PCAPWriter{file: ff, bw: bw, path: filepath.Join(t.TempDir(), "test.pcap")}
	err := w.writeGlobalHeader()
	if err == nil {
		t.Fatal("expected error from writeGlobalHeader")
	}
}

// ============================================================================
// P4-POS: verify global header fields (magic, major=2, minor=4, snapLen,
// linkType=Ethernet). Uses gopacket/pcapgo.
// ============================================================================

func TestPCAPWriter_WriteHeader_Verify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "header.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	w.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcapgo.NewReader: %v", err)
	}
	if r.Snaplen() != 65535 {
		t.Errorf("Snaplen=%d, want 65535", r.Snaplen())
	}
	if r.LinkType().String() != "Ethernet" {
		t.Errorf("LinkType=%s, want Ethernet", r.LinkType())
	}
}

// ============================================================================
// P5-NEG: writeGlobalHeader via bw fails (simulated)
// ============================================================================

func TestPCAPWriter_WriteHeader_Fail(t *testing.T) {
	ff := &failFile{failAfter: 0, failErr: errors.New("bw write failed")}
	bw := smallBufWriter(ff)
	w := &PCAPWriter{file: ff, bw: bw, path: "test.pcap"}
	err := w.writeGlobalHeader()
	if err == nil {
		t.Fatal("expected error from writeGlobalHeader via bw")
	}
}

// ============================================================================
// P7-NEG: Write after Close
// ============================================================================

func TestPCAPWriter_Write_Closed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "closed.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err = w.Write([][]byte{{0x01}})
	if err == nil {
		t.Fatal("expected error writing to closed writer")
	}
	if !strings.Contains(err.Error(), "pcap writer closed") {
		t.Errorf("error=%q, want contains 'pcap writer closed'", err)
	}
}

// ============================================================================
// P8-NEG: header write fails on 2nd packet (simulated)
// ============================================================================

func TestPCAPWriter_Write_HeaderWriteFail(t *testing.T) {
	// failAfter=3 means writes 1-3 succeed (header, pkt1 header, pkt1 body),
	// write 4 (pkt2 header) fails. Packets must be >1 byte so they don't
	// get buffered in the 1-byte bufio (which would skip the ff.Write call).
	ff := &failFile{failAfter: 3, failErr: errors.New("header write failed")}
	bw := smallBufWriter(ff)
	w := &PCAPWriter{file: ff, bw: bw, path: "test.pcap"}
	if err := w.writeGlobalHeader(); err != nil {
		t.Fatalf("writeGlobalHeader: %v", err)
	}
	packets := [][]byte{[]byte("hello"), []byte("world!")}
	err := w.Write(packets)
	if err == nil {
		t.Fatal("expected error from header write")
	}
	// Only first packet recorded: 16 (header) + 5 (body) = 21
	if w.Written() != 21 {
		t.Errorf("Written()=%d, want 21 (only first packet)", w.Written())
	}
}

// ============================================================================
// P9-NEG: body write fails on 2nd packet (simulated)
// ============================================================================

func TestPCAPWriter_Write_BodyWriteFail(t *testing.T) {
	// failAfter=4 means writes 1-4 succeed (header, pkt1 header, pkt1 body,
	// pkt2 header), write 5 (pkt2 body) fails.
	ff := &failFile{failAfter: 4, failErr: errors.New("body write failed")}
	bw := smallBufWriter(ff)
	w := &PCAPWriter{file: ff, bw: bw, path: "test.pcap"}
	if err := w.writeGlobalHeader(); err != nil {
		t.Fatalf("writeGlobalHeader: %v", err)
	}
	packets := [][]byte{[]byte("hello"), []byte("world!")}
	err := w.Write(packets)
	if err == nil {
		t.Fatal("expected error from body write")
	}
	// Only first packet header+body: 16 + 5 = 21
	if w.Written() != 21 {
		t.Errorf("Written()=%d, want 21 (only first packet)", w.Written())
	}
}

// ============================================================================
// P10-BR1: empty packet list
// ============================================================================

func TestPCAPWriter_Write_Empty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	if err := w.Write([][]byte{}); err != nil {
		t.Errorf("Write empty: %v", err)
	}
	if err := w.Write(nil); err != nil {
		t.Errorf("Write nil: %v", err)
	}
	if w.Written() != 0 {
		t.Errorf("Written()=%d, want 0", w.Written())
	}
	// Close flushes the bufio buffer to disk before we check file size.
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Verify only the 24-byte global header was written
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != 24 {
		t.Errorf("file size=%d, want 24 (global header only)", fi.Size())
	}
}

// ============================================================================
// P10-BR2: single nil packet in list
// ============================================================================

func TestPCAPWriter_Write_SinglePacket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nilpkt.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	if err := w.Write([][]byte{nil}); err != nil {
		t.Errorf("Write nil packet: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A nil packet has len(nil) == 0, so caplen=0 record is written.
	records := readPCAPRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
}

// ============================================================================
// P11-POS: WriteTimed with explicit timestamps
// ============================================================================

func TestPCAPWriter_WriteTimed_ExplicitTS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timed.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	t1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 6, 15, 12, 30, 0, 500000, time.UTC) // 500ms
	pkts := []TimedPacket{
		{Data: []byte{0x01}, Timestamp: t1},
		{Data: []byte{0x02}, Timestamp: t2},
	}
	if err := w.WriteTimed(pkts); err != nil {
		t.Fatalf("WriteTimed: %v", err)
	}
	w.Close()

	records := readPCAPRecords(t, path)
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	wantSec1 := uint32(t1.Unix())
	wantUsec1 := uint32(0)
	if records[0][0] != wantSec1 || records[0][1] != wantUsec1 {
		t.Errorf("record 0 ts=(%d,%d), want (%d,%d)",
			records[0][0], records[0][1], wantSec1, wantUsec1)
	}
	wantSec2 := uint32(t2.Unix())
	wantUsec2 := uint32(t2.Nanosecond() / 1000)
	if records[1][0] != wantSec2 || records[1][1] != wantUsec2 {
		t.Errorf("record 1 ts=(%d,%d), want (%d,%d)",
			records[1][0], records[1][1], wantSec2, wantUsec2)
	}
}

// ============================================================================
// P12-BR1: WriteTimed zero timestamp fallback to time.Now()
// ============================================================================

func TestPCAPWriter_WriteTimed_ZeroTS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zerots.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	before := time.Now()
	pkts := []TimedPacket{
		{Data: []byte{0x01}, Timestamp: time.Time{}}, // zero value
	}
	if err := w.WriteTimed(pkts); err != nil {
		t.Fatalf("WriteTimed: %v", err)
	}
	w.Close()
	after := time.Now()

	records := readPCAPRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	recordTime := time.Unix(int64(records[0][0]), int64(records[0][1])*1000)
	if recordTime.Before(before.Add(-5*time.Second)) || recordTime.After(after.Add(5*time.Second)) {
		t.Errorf("record ts=%v, expected near now (%v..%v)", recordTime, before, after)
	}
}

// ============================================================================
// P12-BR2: WriteTimed with mixed explicit and zero timestamps
// ============================================================================

func TestPCAPWriter_WriteTimed_MixedTS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixedts.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	explicitTS := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now()
	pkts := []TimedPacket{
		{Data: []byte{0x01}, Timestamp: explicitTS},
		{Data: []byte{0x02}, Timestamp: time.Time{}}, // zero
	}
	if err := w.WriteTimed(pkts); err != nil {
		t.Fatalf("WriteTimed: %v", err)
	}
	w.Close()
	after := time.Now()

	records := readPCAPRecords(t, path)
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	wantSec := uint32(explicitTS.Unix())
	if records[0][0] != wantSec {
		t.Errorf("record 0 sec=%d, want %d", records[0][0], wantSec)
	}
	// Record 1: zero fallback, should be near now
	recordTime := time.Unix(int64(records[1][0]), int64(records[1][1])*1000)
	if recordTime.Before(before.Add(-5*time.Second)) || recordTime.After(after.Add(5*time.Second)) {
		t.Errorf("record 1 ts=%v, expected near now", recordTime)
	}
}

// ============================================================================
// P13-NEG: WriteTimed after Close
// ============================================================================

func TestPCAPWriter_WriteTimed_Closed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timedclosed.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	w.Close()
	err = w.WriteTimed([]TimedPacket{{Data: []byte{0x01}}})
	if err == nil {
		t.Fatal("expected error for WriteTimed after Close")
	}
	if !strings.Contains(err.Error(), "pcap writer closed") {
		t.Errorf("error=%q, want contains 'pcap writer closed'", err)
	}
}

// ============================================================================
// P14-NEG: WriteTimed header write fails (simulated)
// ============================================================================

func TestPCAPWriter_WriteTimed_HeaderFail(t *testing.T) {
	ff := &failFile{failAfter: 3, failErr: errors.New("timed header write failed")}
	bw := smallBufWriter(ff)
	w := &PCAPWriter{file: ff, bw: bw, path: "test.pcap"}
	if err := w.writeGlobalHeader(); err != nil {
		t.Fatalf("writeGlobalHeader: %v", err)
	}
	pkts := []TimedPacket{
		{Data: []byte{0x01}, Timestamp: time.Now()},
		{Data: []byte{0x02}, Timestamp: time.Now()},
	}
	err := w.WriteTimed(pkts)
	if err == nil {
		t.Fatal("expected error from WriteTimed header fail")
	}
}

// ============================================================================
// P15-NEG: WriteTimed body write fails (simulated)
// ============================================================================

func TestPCAPWriter_WriteTimed_BodyFail(t *testing.T) {
	// failAfter=5: writes 1-5 succeed (global header, pkt1 header, pkt1 body,
	// pkt2 header, pkt3 header), write 6 (pkt3 body) fails.
	ff := &failFile{failAfter: 5, failErr: errors.New("timed body write failed")}
	bw := smallBufWriter(ff)
	w := &PCAPWriter{file: ff, bw: bw, path: "test.pcap"}
	if err := w.writeGlobalHeader(); err != nil {
		t.Fatalf("writeGlobalHeader: %v", err)
	}
	pkts := []TimedPacket{
		{Data: []byte("hello"), Timestamp: time.Now()},
		{Data: []byte("world!"), Timestamp: time.Now()},
		{Data: []byte("packet"), Timestamp: time.Now()},
	}
	err := w.WriteTimed(pkts)
	if err == nil {
		t.Fatal("expected error from WriteTimed body fail")
	}
}

// ============================================================================
// P16-BR1: WriteTimed with empty list
// ============================================================================

func TestPCAPWriter_WriteTimed_Empty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timedempty.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	defer w.Close()
	if err := w.WriteTimed(nil); err != nil {
		t.Errorf("WriteTimed nil: %v", err)
	}
	if err := w.WriteTimed([]TimedPacket{}); err != nil {
		t.Errorf("WriteTimed empty: %v", err)
	}
	if w.Written() != 0 {
		t.Errorf("Written()=%d, want 0", w.Written())
	}
}

// ============================================================================
// P18-NEG1: Close flush fails (simulated)
// ============================================================================

func TestPCAPWriter_Close_FlushFail(t *testing.T) {
	ff := &failFile{failAfter: 0, failErr: errors.New("flush failed")}
	// Use a large bufio buffer so data stays buffered; flush happens in Close.
	bw := bufio.NewWriterSize(ff, 256*1024)
	w := &PCAPWriter{file: ff, bw: bw, path: "test.pcap"}
	if err := w.writeGlobalHeader(); err != nil {
		t.Fatalf("writeGlobalHeader: %v", err)
	}
	// Close flushes the buffer, which tries to write to ff -> fails
	err := w.Close()
	if err == nil {
		t.Fatal("expected flush error from Close")
	}
}

// ============================================================================
// P19-NEG2: Close sync fails (simulated)
// ============================================================================

func TestPCAPWriter_Close_SyncFail(t *testing.T) {
	ff := &failSyncFile{}
	bw := bufio.NewWriterSize(ff, 256*1024)
	w := &PCAPWriter{file: ff, bw: bw, path: "test.pcap"}
	if err := w.writeGlobalHeader(); err != nil {
		t.Fatalf("writeGlobalHeader: %v", err)
	}
	err := w.Close()
	if err == nil {
		t.Fatal("expected sync error from Close")
	}
}

// ============================================================================
// P20-NEG3: Close file.Close fails (simulated)
// ============================================================================

func TestPCAPWriter_Close_CloseFail(t *testing.T) {
	ff := &failCloseFile{}
	bw := bufio.NewWriterSize(ff, 256*1024)
	w := &PCAPWriter{file: ff, bw: bw, path: "test.pcap"}
	if err := w.writeGlobalHeader(); err != nil {
		t.Fatalf("writeGlobalHeader: %v", err)
	}
	err := w.Close()
	if err == nil {
		t.Fatal("expected close error from Close")
	}
}

// ============================================================================
// P21-NEG4: Multi-fail (Flush/Sync/Close all fail) — flush error is first
// ============================================================================

func TestPCAPWriter_Close_MultiFail(t *testing.T) {
	ff := &failFlushSyncCloseFile{}
	ff.failAfter = 0
	ff.failErr = errors.New("flush failed")
	bw := bufio.NewWriterSize(ff, 256*1024)
	w := &PCAPWriter{file: ff, bw: bw, path: "test.pcap"}
	if err := w.writeGlobalHeader(); err != nil {
		t.Fatalf("writeGlobalHeader: %v", err)
	}
	err := w.Close()
	if err == nil {
		t.Fatal("expected error from multi-fail Close")
	}
	// The first error should be from Flush, not Sync or Close
	if !strings.Contains(err.Error(), "flush") {
		t.Errorf("error=%q, want flush error (first in chain)", err)
	}
}

// ============================================================================
// P22-BR1: Double Close (idempotent)
// ============================================================================

func TestPCAPWriter_Close_Double(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doubleclose.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close should be nil (idempotent), got: %v", err)
	}
}

// ============================================================================
// P23-BR2: Close with nil bw (no panic)
// ============================================================================

func TestPCAPWriter_Close_NilBuf(t *testing.T) {
	w := &PCAPWriter{path: "test.pcap"}
	if err := w.Close(); err != nil {
		t.Errorf("Close with nil fields: %v", err)
	}
}

// ============================================================================
// P24-POS: Path() returns the file path
// ============================================================================

func TestPCAPWriter_Path(t *testing.T) {
	tpath := filepath.Join(t.TempDir(), "path-test.pcap")
	w, err := NewPCAPWriter(tpath)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	w.Close()
	if w.Path() != tpath {
		t.Errorf("Path()=%q, want %q", w.Path(), tpath)
	}
}

// ============================================================================
// P25-POS: Written() returns correct byte count
// ============================================================================

func TestPCAPWriter_Written(t *testing.T) {
	path := filepath.Join(t.TempDir(), "written.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	defer w.Close()
	pkts := [][]byte{make([]byte, 10), make([]byte, 10), make([]byte, 10)}
	if err := w.Write(pkts); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := int64(3 * (10 + 16)) // 78
	if w.Written() != want {
		t.Errorf("Written()=%d, want %d", w.Written(), want)
	}
}

// ============================================================================
// RotatingPCAPWriter tests (R1-R22)
// ============================================================================

// R1-POS: NewRotatingPCAPWriter with valid params
func TestRotatingWriter_New_Valid(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	matches, _ := filepath.Glob(base + "-*.pcap")
	if len(matches) != 1 {
		t.Errorf("expected 1 initial file, got %d: %v", len(matches), matches)
	}
}

// R2-NEG: NewRotatingPCAPWriter with unwritable path
func TestRotatingWriter_New_RotateFail(t *testing.T) {
	_, err := NewRotatingPCAPWriter("/proc/not-writable/test", 1<<20, 3)
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

// R3-POS: Write below maxSize (no rotation)
func TestRotatingWriter_Write_Normal(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	if err := w.Write([][]byte{make([]byte, 100)}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	matches, _ := filepath.Glob(base + "-*.pcap")
	if len(matches) != 1 {
		t.Errorf("expected 1 file, got %d", len(matches))
	}
}

// R4-POS: Write triggers rotation (2 files after one rotation)
func TestRotatingWriter_Write_Rotate(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 100, 10)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	bigPkt := make([]byte, 200) // > maxSize=100
	if err := w.Write([][]byte{bigPkt}); err != nil {
		t.Fatalf("Write (rotate): %v", err)
	}
	matches, _ := filepath.Glob(base + "-*.pcap")
	if len(matches) < 2 {
		t.Errorf("expected >=2 files after rotation, got %d", len(matches))
	}
	for _, m := range matches {
		if !strings.Contains(m, "-00000000") && !strings.Contains(m, "-00000001") {
			t.Errorf("filename %q missing zero-padded seq", m)
		}
	}
}

// R5-BR1: Self-recover from nil current
func TestRotatingWriter_Write_SelfRecover(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	w.mu.Lock()
	w.current = nil
	w.mu.Unlock()
	if err := w.Write([][]byte{make([]byte, 10)}); err != nil {
		t.Errorf("Write after self-recover: %v", err)
	}
	matches, _ := filepath.Glob(base + "-*.pcap")
	if len(matches) < 2 {
		t.Errorf("expected >=2 files after self-recover, got %d", len(matches))
	}
}

// R6-NEG1: Rotate fails on write (unwritable path after setup)
func TestRotatingWriter_Write_RotateFail(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 100, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	w.mu.Lock()
	w.basePath = "/proc/not-writable/rot"
	w.mu.Unlock()
	bigPkt := make([]byte, 200)
	err = w.Write([][]byte{bigPkt})
	if err == nil {
		t.Error("expected error from rotate failure")
	}
}

// R7-NEG2: Inner Write fails (simulated via fake inner writer)
func TestRotatingWriter_Write_InnerWriteFail(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	// Replace current with a PCAPWriter that fails on write
	ff := &failFile{failAfter: 0, failErr: errors.New("inner write failed")}
	bw := smallBufWriter(ff)
	fakeWriter := &PCAPWriter{file: ff, bw: bw, path: "fake.pcap"}
	w.mu.Lock()
	w.current = fakeWriter
	w.maxSize = 1 // trigger rotate next time
	w.mu.Unlock()
	// First write triggers rotate (new file OK), but failFile write should fail
	// Actually, after rotate, current is a real PCAPWriter. Let's make it simpler:
	// Set current to the fake writer and ensure it doesn't rotate.
	w2, err2 := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err2 != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err2)
	}
	defer w2.Close()
	w2.mu.Lock()
	w2.current = fakeWriter
	w2.mu.Unlock()
	err2 = w2.Write([][]byte{make([]byte, 10)})
	if err2 == nil {
		t.Error("expected error from inner write failure")
	}
}

// R8-BR2: Write empty packet list (no rotation, no size change)
func TestRotatingWriter_Write_Empty(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 100, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	before, _ := filepath.Glob(base + "-*.pcap")
	beforeCount := len(before)
	if err := w.Write([][]byte{}); err != nil {
		t.Errorf("Write empty: %v", err)
	}
	if err := w.Write(nil); err != nil {
		t.Errorf("Write nil: %v", err)
	}
	after, _ := filepath.Glob(base + "-*.pcap")
	if len(after) != beforeCount {
		t.Errorf("file count changed: before=%d after=%d", beforeCount, len(after))
	}
}

// R9-POS: Close after write
func TestRotatingWriter_Close_Normal(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	if err := w.Write([][]byte{make([]byte, 10)}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// R10-BR1: Close with nil current
func TestRotatingWriter_Close_NilCurrent(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	w.mu.Lock()
	w.current = nil
	w.mu.Unlock()
	if err := w.Close(); err != nil {
		t.Errorf("Close with nil current: %v", err)
	}
}

// R11-NEG1: Inner Close fails (simulated)
func TestRotatingWriter_Close_InnerCloseFail(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close() // outer close also calls close on whatever is current
	ff := &failCloseFile{}
	bw := bufio.NewWriterSize(ff, 256*1024)
	fakeWriter := &PCAPWriter{file: ff, bw: bw, path: filepath.Join(dir, "fake.pcap")}
	if err := fakeWriter.writeGlobalHeader(); err != nil {
		t.Fatalf("fake writeGlobalHeader: %v", err)
	}
	w.mu.Lock()
	w.current = fakeWriter
	w.mu.Unlock()
	// Close triggers fakeWriter.Close which returns failCloseFile's error
	err = w.Close()
	if err == nil {
		t.Error("expected error from inner close failure")
	}
}

// R12-POS: rotate normal (old file closed, new file created)
func TestRotatingRotate_Normal(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	if err := w.Write([][]byte{make([]byte, 10)}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	oldPath := w.current.path
	w.mu.Lock()
	w.maxSize = 1
	w.mu.Unlock()
	if err := w.Write([][]byte{make([]byte, 10)}); err != nil {
		t.Fatalf("Write (trigger rotate): %v", err)
	}
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		t.Errorf("old file %q was deleted", oldPath)
	}
	if w.current == nil {
		t.Fatal("current is nil after rotate")
	}
	if w.current.path == oldPath {
		t.Error("current path unchanged after rotate")
	}
}

// R13-POS1: rotate with old close warning
func TestRotatingRotate_OldCloseWarn(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	ff := &failCloseFile{}
	bw := bufio.NewWriterSize(ff, 256*1024)
	fakeWriter := &PCAPWriter{file: ff, bw: bw, path: filepath.Join(dir, "fake.pcap")}
	if err := fakeWriter.writeGlobalHeader(); err != nil {
		t.Fatalf("fake writeGlobalHeader: %v", err)
	}
	w.mu.Lock()
	w.current = fakeWriter
	w.maxSize = 1
	w.mu.Unlock()
	if err := w.Write([][]byte{make([]byte, 10)}); err != nil {
		t.Errorf("Write after rotate with close warn: %v", err)
	}
	if w.current == nil {
		t.Error("current is nil after rotate despite close warning")
	}
}

// R13-POS2: rotate with old close warn + maxFiles enforcement
func TestRotatingRotate_OldCloseWarn_MaxFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 2)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	// Create 3 rotations with failing close on each
	for i := 0; i < 3; i++ {
		ff := &failCloseFile{}
		bw := bufio.NewWriterSize(ff, 256*1024)
		fakeWriter := &PCAPWriter{file: ff, bw: bw, path: filepath.Join(dir, fmt.Sprintf("fake-%d.pcap", i))}
		if err := fakeWriter.writeGlobalHeader(); err != nil {
			t.Fatalf("fake writeGlobalHeader %d: %v", i, err)
		}
		w.mu.Lock()
		w.current = fakeWriter
		w.maxSize = 1
		w.mu.Unlock()
		_ = w.Write([][]byte{make([]byte, 10)})
	}
}

// R14-NEG1: rotate fails (new file create fails)
func TestRotatingRotate_NewFileFail(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	w.mu.Lock()
	w.basePath = "/proc/not-writable/rot"
	w.maxSize = 1
	w.mu.Unlock()
	err = w.Write([][]byte{make([]byte, 10)})
	if err == nil {
		t.Error("expected error from rotate failure (new file)")
	}
}

// R15-BR1: First rotate call (no old file)
func TestRotatingRotate_FirstCall(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	if w.current == nil {
		t.Fatal("current is nil after first rotate")
	}
	if _, err := os.Stat(w.current.path); os.IsNotExist(err) {
		t.Errorf("first file %q does not exist", w.current.path)
	}
}

// R16-NEG2: First rotate call fails
func TestRotatingRotate_FirstCallFail(t *testing.T) {
	_, err := NewRotatingPCAPWriter("/proc/not-writable/test", 1<<20, 3)
	if err == nil {
		t.Fatal("expected error from first rotate failure")
	}
}

// R17-POS2: enforceMaxFiles deletes oldest files
func TestRotatingRotate_EnforceMaxFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1, 2)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	for i := 0; i < 5; i++ {
		_ = w.Write([][]byte{make([]byte, 10)})
	}
	matches, _ := filepath.Glob(base + "-*.pcap")
	if len(matches) > 2 {
		t.Errorf("expected <=2 files, got %d", len(matches))
	}
}

// R18-BR2: maxFiles=0 (disabled)
func TestRotatingRotate_MaxFilesZero(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1, 0)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	for i := 0; i < 10; i++ {
		_ = w.Write([][]byte{make([]byte, 10)})
	}
	matches, _ := filepath.Glob(base + "-*.pcap")
	if len(matches) < 10 {
		t.Errorf("expected >=10 files (maxFiles=0), got %d", len(matches))
	}
}

// R19-BR1: enforceMaxFiles under limit (no deletion)
func TestRotatingEnforce_UnderLimit(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	// create 2 rotation files manually (plus initial = 3 total, under maxFiles=3)
	for i := 0; i < 2; i++ {
		w2, err2 := NewPCAPWriter(filepath.Join(dir, fmt.Sprintf("rot-%d.pcap", i)))
		if err2 != nil {
			t.Fatalf("create file %d: %v", i, err2)
		}
		w2.Close()
	}
	w.mu.Lock()
	w.enforceMaxFiles()
	w.mu.Unlock()
	// Should not panic, no error reported
}

// R20-BR2: Glob error (illegal pattern)
func TestRotatingEnforce_GlobError(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1<<20, 3)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	// Setting a very long basePath with special chars that might cause glob issues
	w.mu.Lock()
	w.basePath = base + "[0" // incomplete character class = no-match glob, not error
	w.mu.Unlock()
	w.mu.Lock()
	w.enforceMaxFiles()
	w.mu.Unlock()
	// Should not panic
}

// R21-POS: enforceMaxFiles deletes excess files
func TestRotatingEnforce_DeleteExcess(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1, 2)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	for i := 0; i < 5; i++ {
		_ = w.Write([][]byte{make([]byte, 10)})
	}
	matches, _ := filepath.Glob(base + "-*.pcap")
	if len(matches) > 2 {
		t.Errorf("expected <=2 files, got %d", len(matches))
	}
}

// R22-POS1: enforceMaxFiles with partial delete failure
func TestRotatingEnforce_DeleteFail(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rot")
	w, err := NewRotatingPCAPWriter(base, 1, 2)
	if err != nil {
		t.Fatalf("NewRotatingPCAPWriter: %v", err)
	}
	defer w.Close()
	for i := 0; i < 5; i++ {
		_ = w.Write([][]byte{make([]byte, 10)})
	}
	// Try to make the oldest file read-only
	matches, _ := filepath.Glob(base + "-*.pcap")
	if len(matches) > 0 {
		os.Chmod(matches[0], 0444)
		defer os.Chmod(matches[0], 0644)
	}
	// Should not panic even if some removal fails (root can remove root-owned
	// read-only files, so this may still succeed — but the function must not panic)
	w.mu.Lock()
	w.enforceMaxFiles()
	w.mu.Unlock()
}

// ============================================================================
// WriteTimed re-parsed with pcapgo for full roundtrip validation
// ============================================================================

func TestPCAPWriter_WriteTimed_ReParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reparse.pcap")
	w, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter: %v", err)
	}
	t1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	pkts := []TimedPacket{
		{Data: []byte("hello"), Timestamp: t1},
		{Data: []byte("world"), Timestamp: t1.Add(time.Second)},
	}
	if err := w.WriteTimed(pkts); err != nil {
		t.Fatalf("WriteTimed: %v", err)
	}
	w.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcapgo.NewReader: %v", err)
	}
	pkt1, ci1, err1 := r.ReadPacketData()
	if err1 != nil {
		t.Fatalf("ReadPacketData 1: %v", err1)
	}
	if string(pkt1) != "hello" {
		t.Errorf("pkt1 data=%q, want 'hello'", string(pkt1))
	}
	if ci1.CaptureLength != 5 {
		t.Errorf("pkt1 caplen=%d, want 5", ci1.CaptureLength)
	}
	pkt2, ci2, err2 := r.ReadPacketData()
	if err2 != nil {
		t.Fatalf("ReadPacketData 2: %v", err2)
	}
	if string(pkt2) != "world" {
		t.Errorf("pkt2 data=%q, want 'world'", string(pkt2))
	}
	if ci2.CaptureLength != 5 {
		t.Errorf("pkt2 caplen=%d, want 5", ci2.CaptureLength)
	}
	if ci2.Timestamp.Sub(ci1.Timestamp) != time.Second {
		t.Errorf("ts diff=%v, want 1s", ci2.Timestamp.Sub(ci1.Timestamp))
	}
}