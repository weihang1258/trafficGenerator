package pcapparser

// Test points for payload.go, derived from tools/test_points/pcapparser.md
// (components PW1-PW3). REAL tests exercising payloadsWriter directly.

import (
	"path/filepath"
	"strings"
	"testing"
)

// --- PW1: newPayloadsWriter ---

func TestNewPayloadsWriter_EmptyPath(t *testing.T) {
	w, err := newPayloadsWriter("")
	if err != nil {
		t.Fatalf("newPayloadsWriter empty: %v", err)
	}
	if w != nil {
		t.Errorf("newPayloadsWriter('') = %v, want nil", w)
	}
}

func TestNewPayloadsWriter_CreateFail(t *testing.T) {
	w, err := newPayloadsWriter("/no/dir/x.payloads")
	if err == nil || !strings.Contains(err.Error(), "create payloads file") {
		t.Errorf("newPayloadsWriter bad path: err=%v, want 'create payloads file'", err)
	}
	if w != nil {
		t.Errorf("writer = %v, want nil on error", w)
	}
}

func TestNewPayloadsWriter_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.payloads")
	w, err := newPayloadsWriter(path)
	if err != nil {
		t.Fatalf("newPayloadsWriter: %v", err)
	}
	if w == nil {
		t.Fatal("writer = nil, want non-nil")
	}
	if w.offset != 0 {
		t.Errorf("offset = %d, want 0", w.offset)
	}
	w.close()
}

// --- PW2: appendStream ---

func TestAppendStream_NilWriter(t *testing.T) {
	offset, length, err := (*payloadsWriter)(nil).appendStream([]byte("hello"))
	if err != nil {
		t.Fatalf("appendStream nil writer: %v", err)
	}
	if offset != 0 || length != int64(len("hello")) {
		t.Errorf("nil writer: offset=%d length=%d, want 0/%d", offset, length, len("hello"))
	}
}

func TestAppendStream_EmptyData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.payloads")
	w, _ := newPayloadsWriter(path)
	defer w.close()
	offset, length, err := w.appendStream([]byte{})
	if err != nil {
		t.Fatalf("appendStream empty: %v", err)
	}
	if length != 0 {
		t.Errorf("empty data length = %d, want 0", length)
	}
	if offset != 0 {
		t.Errorf("empty data offset = %d, want 0 (no bytes written)", offset)
	}
}

func TestAppendStream_WriteFail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fail.payloads")
	w, _ := newPayloadsWriter(path)
	w.close() // close so the next write fails
	_, _, err := w.appendStream([]byte("data"))
	if err == nil || !strings.Contains(err.Error(), "write payloads") {
		t.Errorf("appendStream after close: err=%v, want 'write payloads'", err)
	}
}

func TestAppendStream_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok.payloads")
	w, _ := newPayloadsWriter(path)
	defer w.close()
	offset, length, err := w.appendStream([]byte("abc"))
	if err != nil {
		t.Fatalf("appendStream: %v", err)
	}
	if offset != 0 || length != 3 {
		t.Errorf("first append: offset=%d length=%d, want 0/3", offset, length)
	}
	// Second append goes to offset 3.
	offset2, length2, err := w.appendStream([]byte("def"))
	if err != nil {
		t.Fatalf("appendStream second: %v", err)
	}
	if offset2 != 3 || length2 != 3 {
		t.Errorf("second append: offset=%d length=%d, want 3/3", offset2, length2)
	}
}

// --- PW3: close ---

func TestPayloadsClose_NilWriter(t *testing.T) {
	err := (*payloadsWriter)(nil).close()
	if err != nil {
		t.Errorf("close nil writer: %v", err)
	}
}

func TestPayloadsClose_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.payloads")
	w, _ := newPayloadsWriter(path)
	err := w.close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	// Second close should error.
	err2 := w.close()
	if err2 == nil {
		t.Error("second close: expected error, got nil")
	}
}