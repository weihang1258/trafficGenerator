package pcapparser

import (
	"fmt"
	"os"
)

// payloadsWriter manages the {pcap_id}.payloads file where reassembled TCP L7
// streams are materialized (§10). All streams' reassembled bytes are concatenated
// in this file; FlowModel stores (offset, length) per direction so a stream can
// be read back with a single ReadAt.
//
// Streams buffer their reassembled bytes in memory (bounded by active-stream
// count); the parser flushes each completed stream's buffer to the file at
// finalize via appendStream. This avoids interleaving conflicts between
// concurrent streams writing to the same file (tcpassembly calls Reassembled
// on different streams in arbitrary order).
type payloadsWriter struct {
	file   *os.File
	offset int64 // append cursor (where the next stream's bytes go)
}

// newPayloadsWriter creates (or truncates) the .payloads file.
func newPayloadsWriter(path string) (*payloadsWriter, error) {
	if path == "" {
		return nil, nil // reassembly disabled (no materialization)
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create payloads file: %w", err)
	}
	return &payloadsWriter{file: f}, nil
}

// appendStream writes a stream's reassembled bytes at the current append cursor
// and returns the (offset, length) of the written region. Called single-threaded
// at finalize. Empty streams (pure-ACK, no payload) take no space -- the caller
// records length 0.
func (w *payloadsWriter) appendStream(data []byte) (offset, length int64, err error) {
	if w == nil || w.file == nil {
		return 0, int64(len(data)), nil // not materialized; still report length
	}
	if len(data) == 0 {
		return w.offset, 0, nil
	}
	offset = w.offset
	if _, err := w.file.WriteAt(data, offset); err != nil {
		return 0, 0, fmt.Errorf("write payloads: %w", err)
	}
	w.offset += int64(len(data))
	return offset, int64(len(data)), nil
}

// close releases the file handle.
func (w *payloadsWriter) close() error {
	if w == nil || w.file == nil {
		return nil
	}
	return w.file.Close()
}
