package stress_test

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
)

// TestGoroutineLeak tests Goroutine leaks
func TestGoroutineLeak(t *testing.T) {
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

	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial goroutines: %d", initialGoroutines)

	const taskCount = 100
	for i := 0; i < taskCount; i++ {
		task := makeTCPTask(fmt.Sprintf("leak-test-task-%d", i), uint16(10000+i))
		err := engine.SubmitTask(task)
		assert.NoError(t, err)
	}

	time.Sleep(3 * time.Second)
	engine.Stop()
	time.Sleep(2 * time.Second)

	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final goroutines: %d", finalGoroutines)

	diff := finalGoroutines - initialGoroutines
	assert.LessOrEqual(t, diff, 10, "Goroutine leak detected: %d goroutines not cleaned up", diff)
}

// TestMemoryLeak tests memory leaks
func TestMemoryLeak(t *testing.T) {
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

	var initialMem runtime.MemStats
	runtime.ReadMemStats(&initialMem)
	t.Logf("Initial memory: Alloc = %v MB, TotalAlloc = %v MB, Sys = %v MB",
		initialMem.Alloc/1024/1024,
		initialMem.TotalAlloc/1024/1024,
		initialMem.Sys/1024/1024)

	const rounds = 10
	const tasksPerRound = 50

	for round := 0; round < rounds; round++ {
		for i := 0; i < tasksPerRound; i++ {
			task := makeTCPTask(fmt.Sprintf("memory-leak-task-%d-%d", round, i), uint16(10000+i))
			engine.SubmitTask(task)
		}

		time.Sleep(1 * time.Second)
		runtime.GC()

		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		t.Logf("Round %d: Alloc = %v MB, TotalAlloc = %v MB",
			round+1,
			mem.Alloc/1024/1024,
			mem.TotalAlloc/1024/1024)
	}

	runtime.GC()
	time.Sleep(1 * time.Second)

	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)
	t.Logf("Final memory: Alloc = %v MB, TotalAlloc = %v MB, Sys = %v MB",
		finalMem.Alloc/1024/1024,
		finalMem.TotalAlloc/1024/1024,
		finalMem.Sys/1024/1024)

	memGrowth := float64(finalMem.Alloc) / float64(initialMem.Alloc)
	assert.LessOrEqual(t, memGrowth, 1.5, "Memory growth too high: %.2fx", memGrowth)
}

// TestBufferLeak tests buffer leaks
func TestBufferLeak(t *testing.T) {
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

	initialStatus := engine.GetBufferStatus()
	t.Logf("Initial buffer status: %+v", initialStatus)

	const batches = 5
	const tasksPerBatch = 20

	for batch := 0; batch < batches; batch++ {
		for i := 0; i < tasksPerBatch; i++ {
			task := makeTCPTask(fmt.Sprintf("buffer-leak-task-%d-%d", batch, i), uint16(10000+i))
			engine.SubmitTask(task)
		}

		time.Sleep(2 * time.Second)

		status := engine.GetBufferStatus()
		t.Logf("Batch %d buffer status: %+v", batch+1, status)

		combined := status["combined"].(map[string]interface{})
		count := combined["count"].(int)
		assert.Less(t, count, 1000, "Buffer count too high, possible leak")
	}

	finalStatus := engine.GetBufferStatus()
	t.Logf("Final buffer status: %+v", finalStatus)
}

// TestResourceCleanup tests resource cleanup
func TestResourceCleanup(t *testing.T) {
	for i := 0; i < 5; i++ {
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

		for j := 0; j < 20; j++ {
			task := makeTCPTask(fmt.Sprintf("cleanup-test-task-%d-%d", i, j), uint16(10000+j))
			engine.SubmitTask(task)
		}

		time.Sleep(1 * time.Second)
		engine.Stop()
		time.Sleep(500 * time.Millisecond)

		t.Logf("Iteration %d completed", i+1)
	}

	time.Sleep(2 * time.Second)
	goroutines := runtime.NumGoroutine()
	t.Logf("Final goroutines after cleanup test: %d", goroutines)
	assert.Less(t, goroutines, 50, "Too many goroutines after cleanup")
}

// TestConnectionLeak tests connection leaks
func TestConnectionLeak(t *testing.T) {
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

	const taskCount = 200
	for i := 0; i < taskCount; i++ {
		task := makeTCPTask(fmt.Sprintf("connection-leak-task-%d", i), uint16(10000+i))
		err := engine.SubmitTask(task)
		assert.NoError(t, err)

		if i%50 == 0 && i > 0 {
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			t.Logf("After %d tasks: Alloc = %v MB, Goroutines = %d",
				i, mem.Alloc/1024/1024, runtime.NumGoroutine())
		}
	}

	time.Sleep(5 * time.Second)

	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)
	t.Logf("Final: Alloc = %v MB, Goroutines = %d",
		finalMem.Alloc/1024/1024, runtime.NumGoroutine())
}
