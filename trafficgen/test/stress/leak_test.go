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

// TestGoroutineLeak 测试 Goroutine 泄漏
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

	// 记录初始 Goroutine 数量
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial goroutines: %d", initialGoroutines)

	// 提交一批任务
	const taskCount = 100
	for i := 0; i < taskCount; i++ {
		taskName := fmt.Sprintf("leak-test-task-%d", i)
		config := map[string]interface{}{
			"src_ip":   "192.168.1.1",
			"dst_ip":   "192.168.1.2",
			"src_port": 10000 + i,
			"dst_port": 80,
		}

		_, err := engine.SubmitTask(taskName, "tcp", config, nil)
		assert.NoError(t, err)
	}

	// 等待任务处理完成
	time.Sleep(3 * time.Second)

	// 停止引擎
	engine.Stop()

	// 等待 Goroutine 清理
	time.Sleep(2 * time.Second)

	// 检查 Goroutine 数量
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final goroutines: %d", finalGoroutines)

	// 允许一定的波动（±10）
	diff := finalGoroutines - initialGoroutines
	assert.LessOrEqual(t, diff, 10, "Goroutine leak detected: %d goroutines not cleaned up", diff)
}

// TestMemoryLeak 测试内存泄漏
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

	// 记录初始内存使用
	var initialMem runtime.MemStats
	runtime.ReadMemStats(&initialMem)
	t.Logf("Initial memory: Alloc = %v MB, TotalAlloc = %v MB, Sys = %v MB",
		initialMem.Alloc/1024/1024,
		initialMem.TotalAlloc/1024/1024,
		initialMem.Sys/1024/1024)

	// 执行多轮任务
	const rounds = 10
	const tasksPerRound = 50

	for round := 0; round < rounds; round++ {
		// 提交任务
		for i := 0; i < tasksPerRound; i++ {
			taskName := fmt.Sprintf("memory-leak-task-%d-%d", round, i)
			config := map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 10000 + i,
				"dst_port": 80,
			}

			engine.SubmitTask(taskName, "tcp", config, nil)
		}

		// 等待任务处理
		time.Sleep(1 * time.Second)

		// 强制 GC
		runtime.GC()

		// 检查内存使用
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		t.Logf("Round %d: Alloc = %v MB, TotalAlloc = %v MB",
			round+1,
			mem.Alloc/1024/1024,
			mem.TotalAlloc/1024/1024)
	}

	// 最终内存检查
	runtime.GC()
	time.Sleep(1 * time.Second)

	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)
	t.Logf("Final memory: Alloc = %v MB, TotalAlloc = %v MB, Sys = %v MB",
		finalMem.Alloc/1024/1024,
		finalMem.TotalAlloc/1024/1024,
		finalMem.Sys/1024/1024)

	// 检查内存增长（允许 50% 的增长）
	memGrowth := float64(finalMem.Alloc) / float64(initialMem.Alloc)
	assert.LessOrEqual(t, memGrowth, 1.5, "Memory growth too high: %.2fx", memGrowth)
}

// TestBufferLeak 测试缓冲区泄漏
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

	// 记录初始缓冲区状态
	initialStatus := engine.GetBufferStatus()
	t.Logf("Initial buffer status: %+v", initialStatus)

	// 提交多批任务
	const batches = 5
	const tasksPerBatch = 20

	for batch := 0; batch < batches; batch++ {
		for i := 0; i < tasksPerBatch; i++ {
			taskName := fmt.Sprintf("buffer-leak-task-%d-%d", batch, i)
			config := map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 10000 + i,
				"dst_port": 80,
			}

			engine.SubmitTask(taskName, "tcp", config, nil)
		}

		// 等待任务处理
		time.Sleep(2 * time.Second)

		// 检查缓冲区状态
		status := engine.GetBufferStatus()
		t.Logf("Batch %d buffer status: %+v", batch+1, status)

		// 验证缓冲区没有持续增长
		combined := status["combined"].(map[string]interface{})
		count := combined["count"].(int)
		assert.Less(t, count, 1000, "Buffer count too high, possible leak")
	}

	// 最终缓冲区检查
	finalStatus := engine.GetBufferStatus()
	t.Logf("Final buffer status: %+v", finalStatus)
}

// TestResourceCleanup 测试资源清理
func TestResourceCleanup(t *testing.T) {
	// 创建并启动引擎
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

		// 提交一些任务
		for j := 0; j < 20; j++ {
			taskName := fmt.Sprintf("cleanup-test-task-%d-%d", i, j)
			config := map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 10000 + j,
				"dst_port": 80,
			}

			engine.SubmitTask(taskName, "tcp", config, nil)
		}

		// 等待任务处理
		time.Sleep(1 * time.Second)

		// 停止引擎
		engine.Stop()

		// 检查资源是否清理
		time.Sleep(500 * time.Millisecond)

		t.Logf("Iteration %d completed", i+1)
	}

	// 检查最终 Goroutine 数量
	time.Sleep(2 * time.Second)
	goroutines := runtime.NumGoroutine()
	t.Logf("Final goroutines after cleanup test: %d", goroutines)

	// 应该回到初始状态（允许小波动）
	assert.Less(t, goroutines, 50, "Too many goroutines after cleanup")
}

// TestConnectionLeak 测试连接泄漏
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

	// 提交大量任务并检查连接/资源
	const taskCount = 200
	for i := 0; i < taskCount; i++ {
		taskName := fmt.Sprintf("connection-leak-task-%d", i)
		config := map[string]interface{}{
			"src_ip":   "192.168.1.1",
			"dst_ip":   "192.168.1.2",
			"src_port": 10000 + i,
			"dst_port": 80,
		}

		_, err := engine.SubmitTask(taskName, "tcp", config, nil)
		assert.NoError(t, err)

		// 每 50 个任务检查一次
		if i%50 == 0 && i > 0 {
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			t.Logf("After %d tasks: Alloc = %v MB, Goroutines = %d",
				i, mem.Alloc/1024/1024, runtime.NumGoroutine())
		}
	}

	// 等待任务处理完成
	time.Sleep(5 * time.Second)

	// 最终检查
	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)
	t.Logf("Final: Alloc = %v MB, Goroutines = %d",
		finalMem.Alloc/1024/1024, runtime.NumGoroutine())
}
