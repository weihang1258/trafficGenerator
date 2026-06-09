package stress_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
)

func makeTCPTask(name string, srcPort uint16) core.Task {
	return core.Task{
		ID:       fmt.Sprintf("stress-%s-%d", name, time.Now().UnixNano()),
		Name:     name,
		Protocol: "tcp",
		Spec: core.FlowSpec{
			SrcIP:   "192.168.1.1",
			DstIP:   "192.168.1.2",
			SrcPort: srcPort,
			DstPort: 80,
			TCP: &core.TCPConfig{
				Handshake:   true,
				Termination: true,
				MSS:         1460,
				WindowSize:  65535,
			},
		},
	}
}

// TestLongRunningTask tests long-running tasks
func TestLongRunningTask(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running test in short mode")
	}

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  4,
		PacketWorkers:  8,
		OutputWorkers:  4,
		BufferSize:     4096,
		QueueSize:      100,
		MaxBufferBytes: 100 * 1024 * 1024,
	})

	engine.RegisterPlanner(tcp.NewPlanner())

	err := engine.Start()
	assert.NoError(t, err)
	defer engine.Stop()

	task := makeTCPTask("long-running-task", 10000)
	err = engine.SubmitTask(task)
	assert.NoError(t, err)

	duration := 5 * time.Minute
	checkInterval := 10 * time.Second
	start := time.Now()

	for time.Since(start) < duration {
		time.Sleep(checkInterval)
		assert.True(t, engine.IsRunning(), "Engine should still be running")
		status := engine.GetBufferStatus()
		assert.NotNil(t, status)
		elapsed := time.Since(start)
		t.Logf("Running for %v, buffer status: %+v", elapsed, status)
	}

	t.Logf("Long-running test completed successfully after %v", duration)
}

// TestRepeatedTaskSubmission tests repeated task submission
func TestRepeatedTaskSubmission(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running test in short mode")
	}

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  4,
		PacketWorkers:  8,
		OutputWorkers:  4,
		BufferSize:     4096,
		QueueSize:      100,
		MaxBufferBytes: 100 * 1024 * 1024,
	})

	engine.RegisterPlanner(tcp.NewPlanner())

	err := engine.Start()
	assert.NoError(t, err)
	defer engine.Stop()

	duration := 30 * time.Minute
	taskInterval := 5 * time.Second
	taskCount := 0
	start := time.Now()

	for time.Since(start) < duration {
		task := makeTCPTask(fmt.Sprintf("repeated-task-%d", taskCount), uint16(10000+(taskCount%1000)))
		err := engine.SubmitTask(task)
		if err != nil {
			t.Logf("Failed to submit task %d: %v", taskCount, err)
		}
		taskCount++
		time.Sleep(taskInterval)
	}

	t.Logf("Submitted %d tasks over %v", taskCount, duration)
}

// TestContinuousLoad tests continuous load
func TestContinuousLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running test in short mode")
	}

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  8,
		PacketWorkers:  16,
		OutputWorkers:  8,
		BufferSize:     8192,
		QueueSize:      200,
		MaxBufferBytes: 200 * 1024 * 1024,
	})

	engine.RegisterPlanner(tcp.NewPlanner())

	err := engine.Start()
	assert.NoError(t, err)
	defer engine.Stop()

	duration := 10 * time.Minute
	batchSize := 10
	batchInterval := 2 * time.Second
	totalTasks := 0
	start := time.Now()

	for time.Since(start) < duration {
		for i := 0; i < batchSize; i++ {
			task := makeTCPTask(fmt.Sprintf("load-task-%d", totalTasks), uint16(10000+(totalTasks%10000)))
			err := engine.SubmitTask(task)
			if err != nil {
				t.Logf("Failed to submit task %d: %v", totalTasks, err)
			}
			totalTasks++
		}

		time.Sleep(batchInterval)
		stats := engine.GetStats()
		t.Logf("Tasks: %d, Stats: %+v", totalTasks, stats)
	}

	t.Logf("Completed continuous load test: %d tasks in %v", totalTasks, duration)
}
