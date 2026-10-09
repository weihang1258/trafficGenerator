package core

// T-ENG-2 (D-ENG-2): GetTaskStatus/RangeTaskStore 快照化锤测。
// 先红(§9.7):预修树上,Writer goroutine 锁内自增 status.Stats 与 Reader
// goroutine 解引用 GetTaskStatus 返回的活指针构成无同步读——-race 必报。
// 修后(锁内值拷贝)同锤测绿。
// 复活验证:若有人把快照改回活指针,本测试在 -race 下重新变红。

import (
	"sync"
	"testing"
	"time"
)

func TestENG2_StatusSnapshot_HammerRace(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 16, QueueSize: 8})
	// 白盒播种(既有惯例:engine_testpoints_test.go 同法):零值 totalConfigs
	// 让 OnPacketWritten 的完成/progress 分支全跳过——纯自增,永不删项。
	e.taskMu.Lock()
	e.taskStore["t-hammer"] = &taskEntry{task: &Task{ID: "t-hammer"}, status: &TaskStatus{TaskID: "t-hammer"}}
	e.taskMu.Unlock()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	// Writers: 锁内写 Stats.PacketsSent(生产者=OutputWorker 的真实写面)。
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					e.OnPacketWritten("t-hammer")
				}
			}
		}()
	}
	// Readers: 解引用 GetTaskStatus 返回值读字段——快照化后这是锁外读拷贝,
	// 活指针时代这是锁外读共享状态(-race 抓的就是这一对)。
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if st, err := e.GetTaskStatus("t-hammer"); err == nil {
						_ = st.Stats.PacketsSent
						_ = st.Progress
					}
					e.RangeTaskStore(func(id string, st *TaskStatus) bool {
						if id == "t-hammer" {
							_ = st.Stats.PacketsSent
						}
						return false
					})
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
