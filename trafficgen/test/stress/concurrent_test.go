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

// TestConcurrentTasks 测试并发任务处理
func TestConcurrentTasks(t *testing.T) {
	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  4,
		PacketWorkers:  8,
		OutputWorkers:  4,
		BufferSize:     4096,
		QueueSize:      100,
		MaxBufferBytes: 100 * 1024 * 1024,
	})

	// 注册协议
	engine.RegisterPlanner(tcp.NewPlanner())
	engine.RegisterPlanner(udp.NewPlanner())

	// 启动引擎
	err := engine.Start()
	assert.NoError(t, err)
	defer engine.Stop()

	// 并发提交任务
	const taskCount = 50
	var wg sync.WaitGroup
	errors := make([]error, taskCount)

	for i := 0; i < taskCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			taskName := fmt.Sprintf("concurrent-task-%d", id)
			protocol := "tcp"
			if id%2 == 0 {
				protocol = "udp"
			}

			config := map[string]interface{}{
				"src_ip":   fmt.Sprintf("192.168.%d.1", id%256),
				"dst_ip":   "192.168.1.2",
				"src_port": 10000 + id,
				"dst_port": 80,
			}

			_, err := engine.SubmitTask(taskName, protocol, config, nil)
			if err != nil {
				errors[id] = err
			}
		}(i)
	}

	// 等待所有任务完成
	wg.Wait()

	// 检查错误
	errorCount := 0
	for _, err := range errors {
		if err != nil {
			errorCount++
			t.Logf("Task error: %v", err)
		}
	}

	t.Logf("Submitted %d tasks, %d errors", taskCount, errorCount)
	assert.Less(t, errorCount, taskCount/10, "Too many task submission errors")
}

// TestHighThroughput 测试高吞吐量
func TestHighThroughput(t *testing.T) {
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

	// 提交大量任务
	const taskCount = 100
	for i := 0; i < taskCount; i++ {
		taskName := fmt.Sprintf("throughput-task-%d", i)
		protocol := "tcp"
		config := map[string]interface{}{
			"src_ip":   "192.168.1.1",
			"dst_ip":   "192.168.1.2",
			"src_port": 10000 + i,
			"dst_port": 80,
		}

		_, err := engine.SubmitTask(taskName, protocol, config, nil)
		assert.NoError(t, err)
	}

	// 等待任务处理
	time.Sleep(5 * time.Second)

	// 检查缓冲区状态
	status := engine.GetBufferStatus()
	assert.NotNil(t, status)

	t.Logf("Buffer status: %+v", status)
}

// TestBurstTasks 测试突发任务
func TestBurstTasks(t *testing.T) {
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

	// 突发提交任务
	const burstSize = 20
	for burst := 0; burst < 5; burst++ {
		for i := 0; i < burstSize; i++ {
			taskName := fmt.Sprintf("burst-%d-task-%d", burst, i)
			config := map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 10000 + burst*burstSize + i,
				"dst_port": 80,
			}

			_, err := engine.SubmitTask(taskName, "tcp", config, nil)
			assert.NoError(t, err)
		}

		// 等待一段时间再提交下一批
		time.Sleep(500 * time.Millisecond)
	}

	// 等待所有任务处理完成
	time.Sleep(3 * time.Second)

	// 检查引擎状态
	assert.True(t, engine.IsRunning())
}

// TestMixedProtocolTasks 测试混合协议任务
func TestMixedProtocolTasks(t *testing.T) {
	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  4,
		PacketWorkers:  8,
		OutputWorkers:  4,
		BufferSize:     4096,
		QueueSize:      100,
		MaxBufferBytes: 100 * 1024 * 1024,
	})

	engine.RegisterPlanner(tcp.NewPlanner())
	engine.RegisterPlanner(udp.NewPlanner())

	err := engine.Start()
	assert.NoError(t, err)
	defer engine.Stop()

	protocols := []string{"tcp", "udp"}
	const tasksPerProtocol = 30

	var wg sync.WaitGroup
	for _, protocol := range protocols {
		for i := 0; i < tasksPerProtocol; i++ {
			wg.Add(1)
			go func(proto string, id int) {
				defer wg.Done()

				taskName := fmt.Sprintf("%s-task-%d", proto, id)
				config := map[string]interface{}{
					"src_ip":   "192.168.1.1",
					"dst_ip":   "192.168.1.2",
					"src_port": 10000 + id,
					"dst_port": 80,
				}

				_, err := engine.SubmitTask(taskName, proto, config, nil)
				assert.NoError(t, err)
			}(protocol, i)
		}
	}

	wg.Wait()

	// 等待任务处理
	time.Sleep(3 * time.Second)

	t.Logf("Submitted %d tasks with mixed protocols", len(protocols)*tasksPerProtocol)
}

// TestTaskSubmissionRate 测试任务提交速率
func TestTaskSubmissionRate(t *testing.T) {
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

	// 测试不同提交速率
	rates := []int{10, 50, 100} // tasks per second

	for _, rate := range rates {
		t.Run(fmt.Sprintf("Rate_%d", rate), func(t *testing.T) {
			duration := 5 * time.Second
			interval := time.Second / time.Duration(rate)
			taskCount := 0

			start := time.Now()
			for time.Since(start) < duration {
				taskName := fmt.Sprintf("rate-task-%d", taskCount)
				config := map[string]interface{}{
					"src_ip":   "192.168.1.1",
					"dst_ip":   "192.168.1.2",
					"src_port": 10000 + taskCount,
					"dst_port": 80,
				}

				_, err := engine.SubmitTask(taskName, "tcp", config, nil)
				if err != nil {
					t.Logf("Failed to submit task %d: %v", taskCount, err)
				}

				taskCount++
				time.Sleep(interval)
			}

			actualRate := float64(taskCount) / time.Since(start).Seconds()
			t.Logf("Target rate: %d tps, Actual rate: %.2f tps", rate, actualRate)
		})
	}
}
