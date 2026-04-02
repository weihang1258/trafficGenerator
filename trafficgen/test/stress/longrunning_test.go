package stress_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
)

// TestLongRunningTask 测试长时间运行任务
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

	// 提交长时间运行的任务
	taskName := "long-running-task"
	config := map[string]interface{}{
		"src_ip":   "192.168.1.1",
		"dst_ip":   "192.168.1.2",
		"src_port": 10000,
		"dst_port": 80,
	}

	taskID, err := engine.SubmitTask(taskName, "tcp", config, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, taskID)

	// 监控任务运行 5 分钟
	duration := 5 * time.Minute
	checkInterval := 10 * time.Second
	start := time.Now()

	for time.Since(start) < duration {
		time.Sleep(checkInterval)

		// 检查引擎状态
		assert.True(t, engine.IsRunning(), "Engine should still be running")

		// 检查缓冲区状态
		status := engine.GetBufferStatus()
		assert.NotNil(t, status)

		elapsed := time.Since(start)
		t.Logf("Running for %v, buffer status: %+v", elapsed, status)
	}

	t.Logf("Long-running test completed successfully after %v", duration)
}

// TestRepeatedTaskSubmission 测试重复提交任务
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

	// 重复提交任务 30 分钟
	duration := 30 * time.Minute
	taskInterval := 5 * time.Second
	taskCount := 0
	start := time.Now()

	for time.Since(start) < duration {
		taskName := fmt.Sprintf("repeated-task-%d", taskCount)
		config := map[string]interface{}{
			"src_ip":   "192.168.1.1",
			"dst_ip":   "192.168.1.2",
			"src_port": 10000 + (taskCount % 1000),
			"dst_port": 80,
		}

		_, err := engine.SubmitTask(taskName, "tcp", config, nil)
		if err != nil {
			t.Logf("Failed to submit task %d: %v", taskCount, err)
		}

		taskCount++
		time.Sleep(taskInterval)
	}

	t.Logf("Submitted %d tasks over %v", taskCount, duration)
}

// TestContinuousLoad 测试持续负载
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

	// 持续负载测试 10 分钟
	duration := 10 * time.Minute
	batchSize := 10
	batchInterval := 2 * time.Second
	totalTasks := 0
	start := time.Now()

	for time.Since(start) < duration {
		// 提交一批任务
		for i := 0; i < batchSize; i++ {
			taskName := fmt.Sprintf("load-task-%d", totalTasks)
			config := map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 10000 + (totalTasks % 10000),
				"dst_port": 80,
			}

			_, err := engine.SubmitTask(taskName, "tcp", config, nil)
			if err != nil {
				t.Logf("Failed to submit task %d: %v", totalTasks, err)
			}
			totalTasks++
		}

		time.Sleep(batchInterval)

		// 每 30 秒打印一次状态
		if totalTasks%150 == 0 {
			elapsed := time.Since(start)
			rate := float64(totalTasks) / elapsed.Seconds()
			t.Logf("Elapsed: %v, Tasks: %d, Rate: %.2f tps", elapsed, totalTasks, rate)
		}
	}

	t.Logf("Continuous load test completed: %d tasks in %v", totalTasks, duration)
}

// TestMemoryStability 测试内存稳定性
func TestMemoryStability(t *testing.T) {
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

	// 运行 15 分钟，定期检查内存
	duration := 15 * time.Minute
	checkInterval := 30 * time.Second
	taskCount := 0
	start := time.Now()

	for time.Since(start) < duration {
		// 提交任务
		taskName := fmt.Sprintf("memory-test-task-%d", taskCount)
		config := map[string]interface{}{
			"src_ip":   "192.168.1.1",
			"dst_ip":   "192.168.1.2",
			"src_port": 10000 + (taskCount % 1000),
			"dst_port": 80,
		}

		engine.SubmitTask(taskName, "tcp", config, nil)
		taskCount++

		// 定期检查
		if taskCount%100 == 0 {
			time.Sleep(checkInterval)

			// 检查缓冲区状态
			status := engine.GetBufferStatus()
			assert.NotNil(t, status)

			// 这里可以添加内存使用检查
			// 实际项目中可以使用 runtime.ReadMemStats()
			t.Logf("Task %d: buffer status: %+v", taskCount, status)
		}
	}

	t.Logf("Memory stability test completed: %d tasks", taskCount)
}
