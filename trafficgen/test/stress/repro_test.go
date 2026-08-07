package stress_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
)

// TestReproWorkerPanic attempts to reproduce the worker.go panic seen in the
// 30-minute stress run: continuous task submission while Stop cycles.
func TestReproWorkerPanic(t *testing.T) {
	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  4,
		PacketWorkers:  8,
		OutputWorkers:  4,
		BufferSize:     4096,
		QueueSize:      100,
		MaxBufferBytes: 100 * 1024 * 1024,
	})
	engine.RegisterPlanner(tcp.NewPlanner())
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			task := makeTCPTask(fmt.Sprintf("repro-%d", i), uint16(10000+(i%1000)))
			if err := engine.SubmitTask(task); err != nil {
				// Engine stopped or full; retry after brief wait.
				time.Sleep(2 * time.Millisecond)
				time.Sleep(2 * time.Millisecond)
			}
			i++
			if i%500 == 0 {
				time.Sleep(1 * time.Millisecond)
			}
			if i > 200000 {
				return
			}
		}
	}()

	// Submit for a bit, then stop and restart several times.
	for cycle := 0; cycle < 5; cycle++ {
		time.Sleep(200 * time.Millisecond)
		engine.Stop()
		if err := engine.Start(); err != nil {
			t.Logf("restart %d err: %v", cycle, err)
		} else {
			t.Logf("restart %d ok", cycle)
		}
	}
	wg.Wait()
	t.Log("repro done")
}