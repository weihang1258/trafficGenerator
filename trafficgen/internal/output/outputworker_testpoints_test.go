package output

// Test points derived from tools/test_points/output.md (OutputWorker section).
// Each test covers a specific test point (O1-O10) with observable assertions.
//
// The O10 data race is fixed by adding statsMu to OutputWorker (output.go),
// so the race test should pass. No t.Skip needed.

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Helper: mockWorkerWriter records calls and optionally fails
// ============================================================================

type mockWorkerWriter struct {
	writeErr  error
	writeCall int
	writeData [][][]byte
	closeCall int
	mu        sync.Mutex
}

func (m *mockWorkerWriter) Write(packets [][]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCall++
	m.writeData = append(m.writeData, packets)
	return m.writeErr
}

func (m *mockWorkerWriter) Close() error {
	m.closeCall++
	return nil
}

// ============================================================================
// O1-POS: NewOutputWorker
// ============================================================================

func TestOutputWorker_New(t *testing.T) {
	ch := make(chan [][]byte)
	var wg sync.WaitGroup
	w := NewOutputWorker(1, ch, &mockWorkerWriter{}, &wg)
	if w == nil {
		t.Fatal("NewOutputWorker returned nil")
	}
	if w.id != 1 {
		t.Errorf("id=%d, want 1", w.id)
	}
	if w.ctx == nil {
		t.Error("ctx is nil")
	}
	if w.cancel == nil {
		t.Error("cancel is nil")
	}
}

// ============================================================================
// O2-POS: Start launches goroutine. Caller is responsible for wg.Add(1).
// ============================================================================

func TestOutputWorker_Start(t *testing.T) {
	ch := make(chan [][]byte, 10)
	var wg sync.WaitGroup
	ow := NewOutputWorker(1, ch, &mockWorkerWriter{}, &wg)
	// Note: Start does not call wg.Add — the caller tracks goroutines.
	// For the wg.Wait below to work, we add here before Start.
	wg.Add(1)
	ow.Start()
	ch <- [][]byte{{0x01}}
	close(ch)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker goroutine did not finish in time")
	}
}

// ============================================================================
// O3-POS: Stop cancels context, goroutine exits
// ============================================================================

func TestOutputWorker_Stop(t *testing.T) {
	ch := make(chan [][]byte)
	var wg sync.WaitGroup
	ow := NewOutputWorker(1, ch, &mockWorkerWriter{}, &wg)
	wg.Add(1)
	ow.Start()
	ow.Stop()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after Stop")
	}
}

// ============================================================================
// O10-NEG: GetStats data race (now fixed with mutex)
// ============================================================================

func TestOutputWorker_GetStats_DataRace(t *testing.T) {
	ch := make(chan [][]byte, 100)
	var wg sync.WaitGroup
	ow := NewOutputWorker(1, ch, &mockWorkerWriter{}, &wg)
	wg.Add(1)
	ow.Start()

	const packets = 50
	done := make(chan struct{})
	go func() {
		for i := 0; i < packets; i++ {
			ch <- [][]byte{make([]byte, 10)}
		}
		close(ch)
	}()

	// Concurrently read stats while worker is processing
	for i := 0; i < 10; i++ {
		go func() {
			for {
				ow.GetStats()
				select {
				case <-done:
					return
				default:
				}
			}
		}()
	}

	wg.Wait()
	close(done)
	stats := ow.GetStats()
	if stats.PacketsWritten != int64(packets) {
		t.Errorf("PacketsWritten=%d, want %d", stats.PacketsWritten, packets)
	}
}

// ============================================================================
// O4-POS: Context cancellation causes goroutine exit
// ============================================================================

func TestOutputWorker_Run_CtxCancel(t *testing.T) {
	ch := make(chan [][]byte)
	var wg sync.WaitGroup
	ow := NewOutputWorker(1, ch, &mockWorkerWriter{}, &wg)
	wg.Add(1)
	ow.Start()
	ow.Stop()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after context cancel")
	}
}

// ============================================================================
// O5-POS1: Channel close causes goroutine exit
// ============================================================================

func TestOutputWorker_Run_ChanClosed(t *testing.T) {
	ch := make(chan [][]byte, 10)
	var wg sync.WaitGroup
	ow := NewOutputWorker(1, ch, &mockWorkerWriter{}, &wg)
	wg.Add(1)
	ow.Start()
	close(ch)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after channel close")
	}
}

// ============================================================================
// O6-POS2: Packet received and written successfully — stats updated
// ============================================================================

func TestOutputWorker_Run_PacketOK(t *testing.T) {
	ch := make(chan [][]byte, 10)
	var wg sync.WaitGroup
	ow := NewOutputWorker(1, ch, &mockWorkerWriter{}, &wg)
	wg.Add(1)
	ow.Start()
	ch <- [][]byte{[]byte("hello"), []byte("world")}
	close(ch)
	wg.Wait()
	stats := ow.GetStats()
	if stats.PacketsWritten != 2 {
		t.Errorf("PacketsWritten=%d, want 2", stats.PacketsWritten)
	}
	if stats.BytesWritten != 10 {
		t.Errorf("BytesWritten=%d, want 10 (5+5)", stats.BytesWritten)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors=%d, want 0", stats.Errors)
	}
}

// ============================================================================
// O7-BR1: Write failure increments Errors, not PacketsWritten/BytesWritten
// ============================================================================

func TestOutputWorker_Run_WriteFail(t *testing.T) {
	ch := make(chan [][]byte, 10)
	var wg sync.WaitGroup
	mw := &mockWorkerWriter{writeErr: errors.New("write failed")}
	ow := NewOutputWorker(1, ch, mw, &wg)
	wg.Add(1)
	ow.Start()
	ch <- [][]byte{[]byte("hello")}
	close(ch)
	wg.Wait()
	stats := ow.GetStats()
	if stats.PacketsWritten != 0 {
		t.Errorf("PacketsWritten=%d, want 0", stats.PacketsWritten)
	}
	if stats.BytesWritten != 0 {
		t.Errorf("BytesWritten=%d, want 0", stats.BytesWritten)
	}
	if stats.Errors != 1 {
		t.Errorf("Errors=%d, want 1", stats.Errors)
	}
}

// ============================================================================
// O8-BR2: ctx cancel + packet available (select race). Send a packet then
// cancel — must not deadlock and must exit cleanly.
// ============================================================================

func TestOutputWorker_Run_CtxAndPacket(t *testing.T) {
	ch := make(chan [][]byte, 100)
	var wg sync.WaitGroup
	ow := NewOutputWorker(1, ch, &mockWorkerWriter{}, &wg)
	wg.Add(1)
	ow.Start()
	ch <- [][]byte{{0x01}}
	ow.Stop()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit cleanly with ctx+cancel race")
	}
}

// ============================================================================
// O9-POS: defer wg.Done always executes (verify via any exit path)
// ============================================================================

func TestOutputWorker_Run_DeferAlways(t *testing.T) {
	// Test 1: exit via ctx cancel
	ch1 := make(chan [][]byte)
	var wg1 sync.WaitGroup
	ow1 := NewOutputWorker(1, ch1, &mockWorkerWriter{}, &wg1)
	wg1.Add(1)
	ow1.Start()
	ow1.Stop()
	wg1.Wait() // must not block

	// Test 2: exit via chan close
	ch2 := make(chan [][]byte, 10)
	var wg2 sync.WaitGroup
	ow2 := NewOutputWorker(2, ch2, &mockWorkerWriter{}, &wg2)
	wg2.Add(1)
	ow2.Start()
	close(ch2)
	wg2.Wait() // must not block

	// Test 3: exit via both (cancel then packet)
	ch3 := make(chan [][]byte, 10)
	var wg3 sync.WaitGroup
	ow3 := NewOutputWorker(3, ch3, &mockWorkerWriter{}, &wg3)
	wg3.Add(1)
	ow3.Start()
	ch3 <- [][]byte{{0x01}}
	ow3.Stop()
	wg3.Wait() // must not block
}