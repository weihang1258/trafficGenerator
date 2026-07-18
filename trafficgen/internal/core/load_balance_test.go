package core

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestShardImbalanceWarn verifies that checkShardBalance emits a WARN log
// when one shard has > 3x the average packet count (spec §7.2).
func TestShardImbalanceWarn(t *testing.T) {
	var buf syncBuffer
	encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.DebugLevel)
	logger := zap.New(core)
	zap.ReplaceGlobals(logger)

	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 100, QueueSize: 10,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// Inflate shard 0 to 300, others 0. Avg = 75, shard 0 = 4x avg -> WARN.
	e.shardCounts[0].Store(300)
	e.shardCounts[1].Store(0)
	e.shardCounts[2].Store(0)
	e.shardCounts[3].Store(0)

	e.checkShardBalance()

	// Give log write a moment
	time.Sleep(50 * time.Millisecond)
	out := buf.String()
	if !strings.Contains(out, "shard load imbalance") {
		t.Fatalf("expected WARN containing 'shard load imbalance', got: %s", out)
	}
}

// TestShardBalanceNoWarnWhenBalanced verifies no WARN when shards are even.
func TestShardBalanceNoWarnWhenBalanced(t *testing.T) {
	var buf syncBuffer
	encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.DebugLevel)
	logger := zap.New(core)
	zap.ReplaceGlobals(logger)

	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 100, QueueSize: 10,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// All shards equal -> no WARN
	for i := range e.shardCounts {
		e.shardCounts[i].Store(100)
	}
	e.checkShardBalance()

	time.Sleep(50 * time.Millisecond)
	out := buf.String()
	if strings.Contains(out, "shard load imbalance") {
		t.Fatalf("expected no WARN when balanced, got: %s", out)
	}
}

// TestShardBalanceNoWarnWhenAllZero verifies no div-by-zero, no WARN on empty.
func TestShardBalanceNoWarnWhenAllZero(t *testing.T) {
	var buf syncBuffer
	encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.DebugLevel)
	logger := zap.New(core)
	zap.ReplaceGlobals(logger)

	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 100, QueueSize: 10,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	for i := range e.shardCounts {
		e.shardCounts[i].Store(0)
	}
	e.checkShardBalance()

	time.Sleep(50 * time.Millisecond)
	out := buf.String()
	if strings.Contains(out, "shard load imbalance") {
		t.Fatalf("expected no WARN when all zero, got: %s", out)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}

func (sb *syncBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.String()
}

// keep atomic import used
var _ = atomic.AddInt64
