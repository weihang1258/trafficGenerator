package output

// Test points derived from tools/test_points/output.md (MultiWriter and
// Manager sections). Existing tests in output_test.go already cover:
//   - TestNewManager (G1)
//   - TestManager_Register (G2/G3/G17)
//   - TestManager_Write (G6)
//   - TestManager_WriteNonExistent (G8)
//   - TestManager_WriteAll (G9)
//   - TestManager_Close (G13)
//   - TestMultiWriter (M3/M11)
//   - TestMultiWriter_AddWriter (M11)
// Only UNCOVERED test points are implemented below.

import (
	"errors"
	"testing"
)

// errMockWriter is a mock Writer that can be configured to fail on Write/Close.
type errMockWriter struct {
	writeFail bool
	closeFail bool
	writeCall int
	closeCall int
}

func (m *errMockWriter) Write(packets [][]byte) error {
	m.writeCall++
	if m.writeFail {
		return errors.New("write failed")
	}
	return nil
}

func (m *errMockWriter) Close() error {
	m.closeCall++
	if m.closeFail {
		return errors.New("close failed")
	}
	return nil
}

// ============================================================================
// MultiWriter tests (M1-M11)
// ============================================================================

// M1-POS: NewMultiWriter with 3 writers
func TestMultiWriter_New_Multiple(t *testing.T) {
	w1 := &errMockWriter{}
	w2 := &errMockWriter{}
	w3 := &errMockWriter{}
	mw := NewMultiWriter(w1, w2, w3)
	if len(mw.writers) != 3 {
		t.Errorf("got %d writers, want 3", len(mw.writers))
	}
}

// M2-BR1: NewMultiWriter with 0 writers
func TestMultiWriter_New_Empty(t *testing.T) {
	mw := NewMultiWriter()
	if mw == nil {
		t.Fatal("NewMultiWriter returned nil")
	}
	if len(mw.writers) != 0 {
		t.Errorf("got %d writers, want 0", len(mw.writers))
	}
}

// M4-BR1: Write with some writers failing
func TestMultiWriter_Write_SomeFail(t *testing.T) {
	w1 := &errMockWriter{writeFail: true}
	w2 := &errMockWriter{}
	w3 := &errMockWriter{writeFail: true}
	mw := NewMultiWriter(w1, w2, w3)
	err := mw.Write([][]byte{{0x01}})
	if err == nil {
		t.Fatal("expected error from Write with some fails")
	}
	// All writers should be called
	if w1.writeCall != 1 || w2.writeCall != 1 || w3.writeCall != 1 {
		t.Errorf("write calls: w1=%d w2=%d w3=%d, want all 1",
			w1.writeCall, w2.writeCall, w3.writeCall)
	}
}

// M5-BR2: Write with all writers failing
func TestMultiWriter_Write_AllFail(t *testing.T) {
	w1 := &errMockWriter{writeFail: true}
	w2 := &errMockWriter{writeFail: true}
	mw := NewMultiWriter(w1, w2)
	err := mw.Write([][]byte{{0x01}})
	if err == nil {
		t.Fatal("expected error from Write with all fails")
	}
	if w1.writeCall != 1 || w2.writeCall != 1 {
		t.Errorf("write calls: w1=%d w2=%d, want both 1", w1.writeCall, w2.writeCall)
	}
}

// M6-BR3: Write with no writers (empty MultiWriter)
func TestMultiWriter_Write_NoWriters(t *testing.T) {
	mw := NewMultiWriter()
	if err := mw.Write([][]byte{{0x01}}); err != nil {
		t.Errorf("Write on empty MultiWriter: %v", err)
	}
}

// M7-POS: Close all OK
func TestMultiWriter_Close_AllOK(t *testing.T) {
	w1 := &errMockWriter{}
	w2 := &errMockWriter{}
	mw := NewMultiWriter(w1, w2)
	if err := mw.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if w1.closeCall != 1 || w2.closeCall != 1 {
		t.Errorf("close calls: w1=%d w2=%d, want both 1", w1.closeCall, w2.closeCall)
	}
}

// M8-BR1: Close with some failing
func TestMultiWriter_Close_SomeFail(t *testing.T) {
	w1 := &errMockWriter{}
	w2 := &errMockWriter{closeFail: true}
	w3 := &errMockWriter{}
	mw := NewMultiWriter(w1, w2, w3)
	err := mw.Close()
	if err == nil {
		t.Fatal("expected error from Close with some fails")
	}
	// All should be called
	if w1.closeCall != 1 || w2.closeCall != 1 || w3.closeCall != 1 {
		t.Errorf("close calls: w1=%d w2=%d w3=%d, want all 1",
			w1.closeCall, w2.closeCall, w3.closeCall)
	}
}

// M9-BR2: Close with all failing
func TestMultiWriter_Close_AllFail(t *testing.T) {
	w1 := &errMockWriter{closeFail: true}
	w2 := &errMockWriter{closeFail: true}
	mw := NewMultiWriter(w1, w2)
	err := mw.Close()
	if err == nil {
		t.Fatal("expected error from Close with all fails")
	}
	if w1.closeCall != 1 || w2.closeCall != 1 {
		t.Errorf("close calls: w1=%d w2=%d, want both 1", w1.closeCall, w2.closeCall)
	}
}

// M10-BR3: Close with no writers (empty MultiWriter)
func TestMultiWriter_Close_NoWriters(t *testing.T) {
	mw := NewMultiWriter()
	if err := mw.Close(); err != nil {
		t.Errorf("Close on empty MultiWriter: %v", err)
	}
}

// ============================================================================
// Manager tests (G4-G18, G1/G2/G3/G6/G8/G9/G13 already in output_test.go)
// ============================================================================

// G4-POS: Get exists
func TestManager_Get_Exists(t *testing.T) {
	mgr := NewManager()
	mgr.Register("test", &errMockWriter{})
	w, ok := mgr.Get("test")
	if !ok {
		t.Fatal("Get('test') should return ok=true")
	}
	if w == nil {
		t.Fatal("Get('test') returned nil writer")
	}
}

// G5-BR1: Get not exists
func TestManager_Get_NotExists(t *testing.T) {
	mgr := NewManager()
	w, ok := mgr.Get("nonexistent")
	if ok {
		t.Error("Get('nonexistent') should return ok=false")
	}
	if w != nil {
		t.Errorf("Get('nonexistent') returned %v, want nil", w)
	}
}

// G7-NEG1: Write fails (writer returns error)
func TestManager_Write_WriteFail(t *testing.T) {
	mgr := NewManager()
	w := &errMockWriter{writeFail: true}
	mgr.Register("test", w)
	err := mgr.Write("test", [][]byte{{0x01}})
	if err == nil {
		t.Error("expected error from Write when writer fails")
	}
}

// G10-BR1: WriteAll with some writers failing
func TestManager_WriteAll_SomeFail(t *testing.T) {
	mgr := NewManager()
	w1 := &errMockWriter{}
	w2 := &errMockWriter{writeFail: true}
	mgr.Register("w1", w1)
	mgr.Register("w2", w2)
	err := mgr.WriteAll([][]byte{{0x01}})
	if err == nil {
		t.Error("expected error from WriteAll with some fails")
	}
	if w1.writeCall != 1 || w2.writeCall != 1 {
		t.Errorf("w1.writeCall=%d w2.writeCall=%d, want both 1", w1.writeCall, w2.writeCall)
	}
}

// G11-BR2: WriteAll with all writers failing
func TestManager_WriteAll_AllFail(t *testing.T) {
	mgr := NewManager()
	w1 := &errMockWriter{writeFail: true}
	w2 := &errMockWriter{writeFail: true}
	mgr.Register("w1", w1)
	mgr.Register("w2", w2)
	err := mgr.WriteAll([][]byte{{0x01}})
	if err == nil {
		t.Error("expected error from WriteAll with all fails")
	}
}

// G12-BR3: WriteAll with empty manager
func TestManager_WriteAll_Empty(t *testing.T) {
	mgr := NewManager()
	if err := mgr.WriteAll([][]byte{{0x01}}); err != nil {
		t.Errorf("WriteAll on empty manager: %v", err)
	}
}

// G14-BR1: Close with some writers failing
func TestManager_Close_SomeFail(t *testing.T) {
	mgr := NewManager()
	w1 := &errMockWriter{}
	w2 := &errMockWriter{closeFail: true}
	mgr.Register("w1", w1)
	mgr.Register("w2", w2)
	err := mgr.Close()
	if err == nil {
		t.Error("expected error from Close with some fails")
	}
	if w1.closeCall != 1 || w2.closeCall != 1 {
		t.Errorf("w1.closeCall=%d w2.closeCall=%d, want both 1", w1.closeCall, w2.closeCall)
	}
	// Map should be empty after Close
	if len(mgr.List()) != 0 {
		t.Error("manager should have no writers after Close")
	}
}

// G15-BR2: Close with all writers failing
func TestManager_Close_AllFail(t *testing.T) {
	mgr := NewManager()
	w1 := &errMockWriter{closeFail: true}
	w2 := &errMockWriter{closeFail: true}
	mgr.Register("w1", w1)
	mgr.Register("w2", w2)
	err := mgr.Close()
	if err == nil {
		t.Error("expected error from Close with all fails")
	}
	if len(mgr.List()) != 0 {
		t.Error("manager should have no writers after Close")
	}
}

// G16-BR3: Close with empty manager
func TestManager_Close_Empty(t *testing.T) {
	mgr := NewManager()
	if err := mgr.Close(); err != nil {
		t.Errorf("Close on empty manager: %v", err)
	}
}

// G17-POS: List returns multiple names
func TestManager_List_Multiple(t *testing.T) {
	mgr := NewManager()
	mgr.Register("a", &errMockWriter{})
	mgr.Register("b", &errMockWriter{})
	mgr.Register("c", &errMockWriter{})
	names := mgr.List()
	if len(names) != 3 {
		t.Errorf("len(List())=%d, want 3", len(names))
	}
	seen := make(map[string]bool)
	for _, n := range names {
		seen[n] = true
	}
	if !seen["a"] || !seen["b"] || !seen["c"] {
		t.Errorf("List()=%v, missing some names", names)
	}
}

// G18-BR1: List with empty manager
func TestManager_List_Empty(t *testing.T) {
	mgr := NewManager()
	names := mgr.List()
	if names == nil {
		t.Error("List() returned nil, want empty slice")
	}
	if len(names) != 0 {
		t.Errorf("len(List())=%d, want 0", len(names))
	}
}