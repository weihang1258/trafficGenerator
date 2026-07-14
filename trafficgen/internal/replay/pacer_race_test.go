package replay

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestPacer_TimestampPacer_ConcurrentSafe verifies that multiple goroutines can
// call Wait on the same TimestampPacer without data races. Must be run with -race.
func TestPacer_TimestampPacer_ConcurrentSafe(t *testing.T) {
	p := &TimestampPacer{multiplier: 1.0}
	ctx := context.Background()
	var wg sync.WaitGroup
	// Each goroutine simulates a PacketWorker with its own packet stream.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(offset int64) {
			defer wg.Done()
			base := time.UnixMicro(offset)
			// 10 packets per worker
			for j := 0; j < 10; j++ {
				pkt := core.PacketConfig{Timestamp: base.Add(time.Duration(j) * 100 * time.Millisecond)}
				p.Wait(ctx, pkt, 0)
			}
		}(int64(i) * 1000)
	}
	wg.Wait()
}

// TestPacer_TokenBucketPacer_ConcurrentSafe verifies the sync.Once lazy init.
func TestPacer_TokenBucketPacer_ConcurrentSafe(t *testing.T) {
	p := &TokenBucketPacer{bps: "100000"}
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				p.Wait(ctx, core.PacketConfig{}, 1500)
			}
		}()
	}
	wg.Wait()
}

// TestPacer_PPSPacer_ConcurrentSafe verifies PPSPacer sync.Once init.
func TestPacer_PPSPacer_ConcurrentSafe(t *testing.T) {
	p := &PPSPacer{pps: 100}
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				p.Wait(ctx, core.PacketConfig{}, 0)
			}
		}()
	}
	wg.Wait()
}
