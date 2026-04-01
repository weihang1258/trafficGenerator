package output

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	mgr := NewManager()
	if mgr == nil {
		t.Fatal("NewManager() returned nil")
	}

	if len(mgr.List()) != 0 {
		t.Error("New manager should have no writers")
	}
}

func TestManager_Register(t *testing.T) {
	mgr := NewManager()

	// Create a mock writer
	writer := &mockWriter{}

	mgr.Register("test", writer)

	if len(mgr.List()) != 1 {
		t.Error("Manager should have 1 writer")
	}

	// Check writer exists
	_, ok := mgr.Get("test")
	if !ok {
		t.Error("Writer 'test' should exist")
	}
}

func TestManager_Write(t *testing.T) {
	mgr := NewManager()
	writer := &mockWriter{}
	mgr.Register("test", writer)

	packets := [][]byte{[]byte("packet1"), []byte("packet2")}
	err := mgr.Write("test", packets)
	if err != nil {
		t.Errorf("Write() error = %v", err)
	}

	if writer.writeCount != 1 {
		t.Errorf("Writer should be called once, got %d", writer.writeCount)
	}
}

func TestManager_WriteNonExistent(t *testing.T) {
	mgr := NewManager()

	packets := [][]byte{[]byte("packet1")}
	err := mgr.Write("nonexistent", packets)
	if err == nil {
		t.Error("Write() should fail for non-existent writer")
	}
}

func TestManager_WriteAll(t *testing.T) {
	mgr := NewManager()
	writer1 := &mockWriter{}
	writer2 := &mockWriter{}

	mgr.Register("w1", writer1)
	mgr.Register("w2", writer2)

	packets := [][]byte{[]byte("packet1")}
	mgr.WriteAll(packets)

	if writer1.writeCount != 1 || writer2.writeCount != 1 {
		t.Error("All writers should be called")
	}
}

func TestManager_Close(t *testing.T) {
	mgr := NewManager()
	writer := &mockWriter{}
	mgr.Register("test", writer)

	mgr.Close()

	if !writer.closed {
		t.Error("Writer should be closed")
	}

	// After close, list should be empty
	if len(mgr.List()) != 0 {
		t.Error("Manager should have no writers after close")
	}
}

func TestMultiWriter(t *testing.T) {
	w1 := &mockWriter{}
	w2 := &mockWriter{}

	mw := NewMultiWriter(w1, w2)

	packets := [][]byte{[]byte("packet1")}
	err := mw.Write(packets)
	if err != nil {
		t.Errorf("Write() error = %v", err)
	}

	if w1.writeCount != 1 || w2.writeCount != 1 {
		t.Error("Both writers should be called")
	}
}

func TestMultiWriter_AddWriter(t *testing.T) {
	w1 := &mockWriter{}
	mw := NewMultiWriter(w1)

	w2 := &mockWriter{}
	mw.AddWriter(w2)

	packets := [][]byte{[]byte("packet1")}
	mw.Write(packets)

	if w1.writeCount != 1 || w2.writeCount != 1 {
		t.Error("Both writers should be called after AddWriter")
	}
}

// mockWriter is a mock implementation of Writer for testing
type mockWriter struct {
	writeCount int
	closed     bool
}

func (m *mockWriter) Write(packets [][]byte) error {
	m.writeCount++
	return nil
}

func (m *mockWriter) Close() error {
	m.closed = true
	return nil
}
