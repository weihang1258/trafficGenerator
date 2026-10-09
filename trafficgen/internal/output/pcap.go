package output

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// PCAP file header constants.
const (
	pcapMagicNumber  = 0xa1b2c3d4
	pcapVersionMajor = 2
	pcapVersionMinor = 4
	pcapSnapLen      = 65535
	pcapLinkType     = 1 // Ethernet
)

// pcapFile is the subset of *os.File this package uses. Declared as an
// interface so tests can inject fake files to simulate Sync/Close failures
// (real *os.File.Close/Sync rarely fail, making failure-path coverage
// impossible without this). *os.File satisfies this interface.
type pcapFile interface {
	io.Writer
	Close() error
	Sync() error
}

// PCAPWriter writes packets to a PCAP file. Writes are buffered (bufio) and
// each packet gets its own timestamp; fsync happens only on Close, not per
// Write, so high packet rates do not stall on disk flushes.
type PCAPWriter struct {
	file    pcapFile
	bw      *bufio.Writer
	path    string
	mu      sync.Mutex
	written int64
	// maxBytes caps the on-disk file size (24B global header included);
	// 0 = unbounded. truncated records a planned ceiling stop.
	maxBytes  int64
	truncated bool
}

// NewPCAPWriter creates a new PCAP writer.
func NewPCAPWriter(path string) (*PCAPWriter, error) {
	return NewPCAPWriterWithCap(path, 0)
}

// NewPCAPWriterWithCap creates a PCAP writer capped at maxBytes on-disk
// (global header included); 0 means unbounded. When the next record would
// exceed the cap the writer sets the truncated flag and stops accepting
// further records — Write/WriteTimed return nil (a planned ceiling, not an
// error). The check runs BEFORE any byte of the record is buffered, so the
// file always ends on a complete record and stays a valid pcap.
func NewPCAPWriterWithCap(path string, maxBytes int64) (*PCAPWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap file: %w", err)
	}

	writer := &PCAPWriter{
		file:     file,
		bw:       bufio.NewWriterSize(file, 256*1024),
		path:     path,
		maxBytes: maxBytes,
	}

	// Write PCAP global header
	if err := writer.writeGlobalHeader(); err != nil {
		file.Close()
		return nil, err
	}

	return writer, nil
}

// writeGlobalHeader writes the PCAP global header.
func (w *PCAPWriter) writeGlobalHeader() error {
	header := make([]byte, 24)

	// Magic number
	binary.LittleEndian.PutUint32(header[0:4], pcapMagicNumber)

	// Version
	binary.LittleEndian.PutUint16(header[4:6], pcapVersionMajor)
	binary.LittleEndian.PutUint16(header[6:8], pcapVersionMinor)

	// Timezone offset (usually 0)
	binary.LittleEndian.PutUint32(header[8:12], 0)

	// Timestamp accuracy (usually 0)
	binary.LittleEndian.PutUint32(header[12:16], 0)

	// Snaplen
	binary.LittleEndian.PutUint32(header[16:20], pcapSnapLen)

	// Link type (Ethernet)
	binary.LittleEndian.PutUint32(header[20:24], pcapLinkType)

	_, err := w.bw.Write(header)
	return err
}

// Write writes packets to the PCAP file. Each packet gets its own timestamp
// (computed per-packet inside the loop), the 16-byte record header and packet
// body are written as a single buffered write. The buffer is NOT flushed here:
// bufio auto-flushes when the 256KB buffer fills, and fsync happens on Close.
// Per-Write Flush would defeat the bufio buffer (one syscall per packet).
func (w *PCAPWriter) Write(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return fmt.Errorf("pcap writer closed: %s", w.path)
	}

	var buf [16]byte
	for _, packet := range packets {
		if w.hitCap(int64(len(packet))) {
			break
		}
		now := time.Now()
		binary.LittleEndian.PutUint32(buf[0:4], uint32(now.Unix()))
		binary.LittleEndian.PutUint32(buf[4:8], uint32(now.Nanosecond()/1000))
		caplen := uint32(len(packet))
		binary.LittleEndian.PutUint32(buf[8:12], caplen)
		binary.LittleEndian.PutUint32(buf[12:16], caplen)

		// Header + body in one buffered write (avoids two syscalls per packet).
		if _, err := w.bw.Write(buf[:]); err != nil {
			return err
		}
		if _, err := w.bw.Write(packet); err != nil {
			return err
		}
		w.written += int64(len(packet)) + 16
	}

	return nil
}

// TimedPacket pairs a packet's bytes with its scheduled send timestamp (§12).
// PCAPWriter.WriteTimed uses this instead of time.Now() so the output pcap
// reflects the actual replay rhythm, not the wall-clock write instant.
type TimedPacket struct {
	Data      []byte
	Timestamp time.Time
}

// WriteTimed writes packets with explicit timestamps (scheduled send time).
// This is the preferred write path for replay pcap output (§12: "输出 pcap
// 时间戳：用计划发送时刻"). Falls back to time.Now() for any packet whose
// timestamp is the zero value.
func (w *PCAPWriter) WriteTimed(packets []TimedPacket) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return fmt.Errorf("pcap writer closed: %s", w.path)
	}

	var buf [16]byte
	for _, tp := range packets {
		if w.hitCap(int64(len(tp.Data))) {
			break
		}
		ts := tp.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		binary.LittleEndian.PutUint32(buf[0:4], uint32(ts.Unix()))
		binary.LittleEndian.PutUint32(buf[4:8], uint32(ts.Nanosecond()/1000))
		caplen := uint32(len(tp.Data))
		binary.LittleEndian.PutUint32(buf[8:12], caplen)
		binary.LittleEndian.PutUint32(buf[12:16], caplen)

		if _, err := w.bw.Write(buf[:]); err != nil {
			return err
		}
		if _, err := w.bw.Write(tp.Data); err != nil {
			return err
		}
		w.written += int64(len(tp.Data)) + 16
	}

	return nil
}

// Close closes the PCAP file.
func (w *PCAPWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		// Flush buffered writes, then fsync so data reaches disk on close.
		var err error
		if w.bw != nil {
			if flushErr := w.bw.Flush(); flushErr != nil {
				err = flushErr
			}
		}
		if syncErr := w.file.Sync(); syncErr != nil && err == nil {
			err = syncErr
		}
		if closeErr := w.file.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		w.file = nil
		return err
	}
	return nil
}

// Path returns the file path.
func (w *PCAPWriter) Path() string {
	return w.path
}

// Written returns the total bytes written.
func (w *PCAPWriter) Written() int64 {
	return w.written
}

// Truncated reports whether the size cap stopped the writer early. The file
// is still a valid pcap — every record it contains is complete.
func (w *PCAPWriter) Truncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncated
}

// Final: a directly-owned PCAPWriter has exactly one consumer, so its Close
// always finalizes the file (D-ENG-1 shared-writer probing contract).
func (w *PCAPWriter) Final() bool { return true }

// hitCap applies the size ceiling for one incoming record (16B record header
// + body). written counts payload+16 only, so the real file size is
// 24 (global header) + written. Must be called under w.mu (both Write paths
// hold it).
func (w *PCAPWriter) hitCap(bodyLen int64) bool {
	if w.maxBytes > 0 && 24+w.written+16+bodyLen > w.maxBytes {
		w.truncated = true
		return true
	}
	return false
}

// SharedPCAPWriter lets several writers (one per strategy of a multi-strategy
// task) share ONE underlying PCAPWriter on the same file path. Without it each
// strategy's os.Create truncates the previous product and the independent fds
// interleave-write over each other (D-ENG-1). Writes delegate directly —
// PCAPWriter's mu serializes them record-by-record, so interleaved records
// stay complete. Release drops the refcount; the LAST release fsync-closes
// the file.
type SharedPCAPWriter struct {
	pw   *PCAPWriter
	mu   sync.Mutex
	refs int
}

// NewSharedPCAPWriter opens (or truncates) the file once with the given size
// cap (0 = unbounded). Every consumer must AddRef before use and Release via
// Close when done; the file is final when the last reference releases.
func NewSharedPCAPWriter(path string, maxBytes int64) (*SharedPCAPWriter, error) {
	pw, err := NewPCAPWriterWithCap(path, maxBytes)
	if err != nil {
		return nil, err
	}
	return &SharedPCAPWriter{pw: pw}, nil
}

// AddRef registers one consumer. Call before handing the writer out; balance
// every AddRef with exactly one Release (adapters guard with sync.Once).
func (s *SharedPCAPWriter) AddRef() {
	s.mu.Lock()
	s.refs++
	s.mu.Unlock()
}

// Write delegates to the underlying PCAPWriter.
func (s *SharedPCAPWriter) Write(packets [][]byte) error { return s.pw.Write(packets) }

// WriteTimed delegates to the underlying PCAPWriter.
func (s *SharedPCAPWriter) WriteTimed(tp []TimedPacket) error { return s.pw.WriteTimed(tp) }

// Truncated delegates the cap probe.
func (s *SharedPCAPWriter) Truncated() bool { return s.pw.Truncated() }

// Release drops one reference and reports whether THIS release was the last
// (file actually closed/final); the last release returns the Close error.
func (s *SharedPCAPWriter) Release() (final bool, err error) {
	s.mu.Lock()
	s.refs--
	if s.refs > 0 {
		s.mu.Unlock()
		return false, nil
	}
	s.mu.Unlock()
	return true, s.pw.Close()
}

// RotatingPCAPWriter writes to rotating PCAP files.
type RotatingPCAPWriter struct {
	basePath    string
	maxSize     int64 // Max file size in bytes
	maxFiles    int   // Max number of files to keep
	current     *PCAPWriter
	currentSize int64
	rotation    int64 // monotonic counter for unique filenames
	mu          sync.Mutex
}

// NewRotatingPCAPWriter creates a new rotating PCap writer.
func NewRotatingPCAPWriter(basePath string, maxSize int64, maxFiles int) (*RotatingPCAPWriter, error) {
	writer := &RotatingPCAPWriter{
		basePath: basePath,
		maxSize:  maxSize,
		maxFiles: maxFiles,
	}

	if err := writer.rotate(); err != nil {
		return nil, err
	}

	return writer, nil
}

// Write writes packets to the current PCAP file.
func (w *RotatingPCAPWriter) Write(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Calculate total size
	var totalSize int64
	for _, p := range packets {
		totalSize += int64(len(p) + 16)
	}

	// Rotate when the current file would exceed maxSize, or when a prior
	// rotate() failed and left w.current == nil. Treating nil as a rotation
	// trigger makes the writer self-recover: after a transient NewPCAPWriter
	// failure (disk full, EMFILE, ...), the next Write retries rotation
	// instead of staying wedged on a closed inner writer forever.
	if w.current == nil || w.currentSize+totalSize > w.maxSize {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	if err := w.current.Write(packets); err != nil {
		return err
	}

	w.currentSize += totalSize
	return nil
}

// Close closes the current file.
func (w *RotatingPCAPWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.current != nil {
		return w.current.Close()
	}
	return nil
}

// rotate creates a new PCAP file. It closes the previous file (propagating
// close errors to the log), uses a monotonic counter in the filename so two
// rotations within the same second do not collide and truncate each other,
// and enforces maxFiles by deleting the oldest files.
func (w *RotatingPCAPWriter) rotate() error {
	// Close current file, surfacing close errors (flush/fsync) rather than
	// silently dropping data.
	if w.current != nil {
		if err := w.current.Close(); err != nil {
			zap.L().Warn("previous pcap file close error (possible data loss)",
				zap.String("path", w.current.path),
				zap.Error(err),
			)
		}
	}
	// Drop the reference and reset the size BEFORE creating the new file. If
	// NewPCAPWriter fails below, w.current stays nil so the next Write retries
	// rotation (via the w.current == nil trigger) instead of calling Write on
	// the just-closed inner writer and wedging on its closed-state guard.
	w.current = nil
	w.currentSize = 0

	// Monotonic counter guarantees uniqueness even when two rotations happen
	// in the same second (second-granularity timestamps alone collide and
	// os.Create would truncate the prior file). Zero-padded so lexical sort
	// of filenames matches numeric order (otherwise seq>=10 mis-sorts and
	// enforceMaxFiles could delete the currently-open file). %09d keeps
	// lexical == numeric order up to 999,999,999 rotations, far beyond any
	// realistic session (%05d would re-break at 100,000 same-second rotations).
	seq := atomic.AddInt64(&w.rotation, 1)
	timestamp := time.Now().Format("20060102-150405")
	path := fmt.Sprintf("%s-%s-%09d.pcap", w.basePath, timestamp, seq)

	// Create new file
	writer, err := NewPCAPWriter(path)
	if err != nil {
		// Leave w.current == nil and currentSize == 0 (set above) so the next
		// Write retries rotation via the w.current == nil trigger instead of
		// hitting the closed-writer guard on a stale, closed inner writer.
		return err
	}

	w.current = writer
	w.currentSize = 0

	zap.L().Info("rotated pcap file", zap.String("path", path))

	// Enforce maxFiles: delete oldest files beyond the limit.
	if w.maxFiles > 0 {
		w.enforceMaxFiles()
	}

	return nil
}

// enforceMaxFiles deletes the oldest rotated files beyond maxFiles. Files are
// matched by the basePath-*.pcap glob and sorted by name (timestamp+seq).
func (w *RotatingPCAPWriter) enforceMaxFiles() {
	pattern := w.basePath + "-*.pcap"
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) <= w.maxFiles {
		return
	}
	// Sort by name; oldest first (timestamp in name makes lexical order ~chronological).
	sort.Strings(matches)
	excess := len(matches) - w.maxFiles
	for i := 0; i < excess; i++ {
		if rmErr := os.Remove(matches[i]); rmErr != nil {
			zap.L().Warn("failed to remove old pcap file",
				zap.String("path", matches[i]),
				zap.Error(rmErr),
			)
		}
	}
}
