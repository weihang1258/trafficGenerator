package output

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
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

// PCAPWriter writes packets to a PCAP file. Writes are buffered (bufio) and
// each packet gets its own timestamp; fsync happens only on Close, not per
// Write, so high packet rates do not stall on disk flushes.
type PCAPWriter struct {
	file    *os.File
	bw      *bufio.Writer
	path    string
	mu      sync.Mutex
	written int64
}

// NewPCAPWriter creates a new PCAP writer.
func NewPCAPWriter(path string) (*PCAPWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap file: %w", err)
	}

	writer := &PCAPWriter{
		file: file,
		bw:   bufio.NewWriterSize(file, 256*1024),
		path: path,
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
// body are written as a single buffered write, and the buffer is flushed (not
// fsynced) so high packet rates do not stall on disk flushes.
func (w *PCAPWriter) Write(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var buf [16]byte
	for _, packet := range packets {
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

	return w.bw.Flush()
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

// RotatingPCAPWriter writes to rotating PCAP files.
type RotatingPCAPWriter struct {
	basePath    string
	maxSize     int64 // Max file size in bytes
	maxFiles    int   // Max number of files to keep
	current     *PCAPWriter
	currentSize int64
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

	// Check if rotation needed
	if w.currentSize+totalSize > w.maxSize {
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

// rotate creates a new PCAP file.
func (w *RotatingPCAPWriter) rotate() error {
	// Close current file
	if w.current != nil {
		w.current.Close()
	}

	// Generate new filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	path := fmt.Sprintf("%s-%s.pcap", w.basePath, timestamp)

	// Create new file
	writer, err := NewPCAPWriter(path)
	if err != nil {
		return err
	}

	w.current = writer
	w.currentSize = 0

	zap.L().Info("rotated pcap file", zap.String("path", path))

	// TODO: Clean up old files if maxFiles exceeded

	return nil
}
