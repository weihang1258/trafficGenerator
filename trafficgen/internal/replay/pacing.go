package replay

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Pacer controls the send rate of replay packets (§16.9). Called after the
// buildFunc produces the final bytes, with the real packet size. Two families:
//   - TimestampPacer (original/multiplier): sleeps to the scheduled send time,
//     absorbing drift so a late packet doesn't cause a catch-up burst.
//   - TokenBucketPacer / PPSPacer / MaxPacer (bps/pps/max): rate-based.
type Pacer interface {
	// Wait blocks until the packet should be sent. size is the built packet's
	// byte length (used by bps; ignored by timestamp/max). pkt carries the
	// capture timestamp (used by timestamp pacing).
	Wait(ctx context.Context, pkt core.PacketConfig, size int) error
}

// NewPacer selects a Pacer for the given speed mode.
func NewPacer(speed ReplaySpeed) Pacer {
	switch speed.Mode {
	case "original":
		return &TimestampPacer{multiplier: 1.0}
	case "multiplier":
		m := speed.Multiplier
		if m <= 0 {
			m = 1.0
		}
		return &TimestampPacer{multiplier: m}
	case "bps":
		return &TokenBucketPacer{bps: speed.BPS}
	// pps removed per audit: speed.mode only supports original/multiplier/bps/"".
	// Case "pps" intentionally omitted -- unknown modes fall through to MaxPacer.
	case "max", "":
		return &MaxPacer{}
	}
	return &MaxPacer{}
}

// TimestampPacer paces by the pcap capture timestamps (§10). It sleeps to the
// scheduled send time = startWall + (captureTs - firstTs) * multiplier + drift.
// If a packet is late (scheduled in the past), the drift offset is shifted
// forward so the current packet sends immediately and subsequent packets
// resume spacing from now -- no catch-up burst, no packet drop, relative order
// preserved.
//
// Wait is safe for concurrent use (mutex protects mutable state) to support
// multiple PacketWorkers calling Wait on the same Pacer instance.
type TimestampPacer struct {
	mu sync.Mutex

	multiplier float64
	firstTsUs  int64
	startWall  time.Time
	init       bool
	drift      time.Duration // accumulated drift absorption
}

func (p *TimestampPacer) Wait(ctx context.Context, pkt core.PacketConfig, size int) error {
	p.mu.Lock()
	tsUs := pkt.Timestamp.UnixMicro()
	if !p.init {
		p.firstTsUs = tsUs
		p.startWall = time.Now()
		p.init = true
		p.mu.Unlock()
		return nil
	}
	delta := time.Duration(float64(tsUs-p.firstTsUs) * p.multiplier * float64(time.Microsecond))
	scheduled := p.startWall.Add(delta).Add(p.drift)
	p.mu.Unlock()
	now := time.Now()
	if scheduled.After(now) {
		select {
		case <-time.After(scheduled.Sub(now)):
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		// Late: absorb the lateness into drift so we don't burst to catch up.
		p.mu.Lock()
		p.drift += now.Sub(scheduled)
		p.mu.Unlock()
	}
	return nil
}

// MaxPacer sends as fast as possible (no limiting).
type MaxPacer struct{}

func (MaxPacer) Wait(context.Context, core.PacketConfig, int) error { return nil }

// TokenBucketPacer limits by bytes/sec (bps mode). It uses a core.TokenBucket
// seeded with the parsed rate. Wait is safe for concurrent use -- the underlying
// TokenBucket has its own mutex, and the lazy init uses a sync.Once.
type TokenBucketPacer struct {
	bps    string
	once   sync.Once
	bucket *core.TokenBucket
}

func (p *TokenBucketPacer) Wait(ctx context.Context, pkt core.PacketConfig, size int) error {
	p.once.Do(func() {
		bps, err := core.ParseBPS(p.bps)
		if err != nil || bps <= 0 {
			return
		}
		rateBytesPerSec := bps / 8
		if rateBytesPerSec < 1 {
			rateBytesPerSec = 1
		}
		p.bucket = core.NewTokenBucket(rateBytesPerSec, 65536)
	})
	if p.bucket == nil {
		return nil
	}
	return p.bucket.Wait(ctx, int64(size))
}

// PPSPacer limits by packets/sec (pps mode) via a fixed inter-packet sleep.
// Wait is safe for concurrent use: a mutex serializes the sleeps so that N
// PacketWorkers sharing one PPSPacer collectively emit at `pps` (not N×pps).
// Without the mutex each worker would sleep independently and the aggregate
// rate would scale with the worker count.
type PPSPacer struct {
	pps      float64
	once     sync.Once
	interval time.Duration
	mu       sync.Mutex // serializes Wait across workers for a global PPS rate
}

func (p *PPSPacer) Wait(ctx context.Context, _ core.PacketConfig, _ int) error {
	p.once.Do(func() {
		if p.pps > 0 {
			p.interval = time.Duration(float64(time.Second) / p.pps)
		}
	})
	if p.interval <= 0 {
		return nil
	}
	// Hold the mutex across the sleep so concurrent workers queue behind it,
	// enforcing the global inter-packet interval (§16.2 "类内共享桶").
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-time.After(p.interval):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// parseBPSRate is a thin wrapper for tests; production uses core.ParseBPS.
func parseBPSRate(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
