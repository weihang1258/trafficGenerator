package stress_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
)

// TestConcurrentTaskSubmission tests concurrent task submission
func TestConcurrentTaskSubmission(t *testing.T) {
	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  8,
		PacketWorkers:  16,
		OutputWorkers:  8,
		BufferSize:     8192,
		QueueSize:      200,
		MaxBufferBytes: 200 * 1024 * 1024,
	})

	engine.RegisterPlanner(tcp.NewPlanner())
	engine.RegisterPlanner(udp.NewPlanner())

	err := engine.Start()
	assert.NoError(t, err)
	defer engine.Stop()

	const numGoroutines = 10
	const tasksPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < tasksPerGoroutine; i++ {
				task := makeTCPTask(fmt.Sprintf("concurrent-task-%d-%d", goroutineID, i), uint16(10000+goroutineID*100+i))
				engine.SubmitTask(task)
			}
		}(g)
	}

	wg.Wait()
	time.Sleep(5 * time.Second)

	stats := engine.GetStats()
	t.Logf("Engine stats after concurrent submission: %+v", stats)

	totalPackets := stats["config_workers"].(map[string]interface{})["packets"].(int64)
	assert.Greater(t, totalPackets, int64(0), "Should have generated packets")
}

// TestMixedProtocolConcurrent tests concurrent mixed protocol tasks
func TestMixedProtocolConcurrent(t *testing.T) {
	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  8,
		PacketWorkers:  16,
		OutputWorkers:  8,
		BufferSize:     8192,
		QueueSize:      200,
		MaxBufferBytes: 200 * 1024 * 1024,
	})

	engine.RegisterPlanner(tcp.NewPlanner())
	engine.RegisterPlanner(udp.NewPlanner())

	err := engine.Start()
	assert.NoError(t, err)
	defer engine.Stop()

	var wg sync.WaitGroup
	wg.Add(2)

	// TCP goroutine
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			task := makeTCPTask(fmt.Sprintf("tcp-concurrent-%d", i), uint16(20000+i))
			engine.SubmitTask(task)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// UDP goroutine
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			task := core.Task{
				ID:       fmt.Sprintf("udp-concurrent-%d-%d", i, time.Now().UnixNano()),
				Name:     fmt.Sprintf("udp-concurrent-%d", i),
				Protocol: "udp",
				Spec: core.FlowSpec{
					SrcIP:   "192.168.1.1",
					DstIP:   "192.168.1.2",
					SrcPort: uint16(30000 + i),
					DstPort: 53,
				},
			}
			engine.SubmitTask(task)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()
	time.Sleep(3 * time.Second)

	stats := engine.GetStats()
	t.Logf("Mixed protocol stats: %+v", stats)
}