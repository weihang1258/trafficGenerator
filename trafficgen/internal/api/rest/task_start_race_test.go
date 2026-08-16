package rest

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/protocol/modbus"
	"github.com/trafficgen/trafficgen/internal/storage"
)

func TestTaskStart_PlanErrorMarksTaskFailed(t *testing.T) {
	// Regression: a task whose planner rejects the spec at Plan() time must end
	// in "failed", not wedge in "running" forever. The engine can consume and
	// fail the task immediately after SubmitTask; the DB "running" save must
	// happen BEFORE SubmitTask so onEngineTaskComplete sees "running" and
	// records the failure (previously the late save clobbered it).
	gin.SetMode(gin.TestMode)
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	e.RegisterPlanner(modbus.NewPlanner())

	sid := createTestStrategy(t, db, "test-user", "s1", "modbus")
	db.Model(&storage.StrategyModel{}).Where("id = ?", sid).Update("config", `{"modbus":{"host":"10.0.0.1","port":502,"transactions":[{"function_code":42}]}}`)
	sidsJSON, _ := json.Marshal([]string{sid})
	taskID := uuid.New().String()
	pcapPath := t.TempDir() + "/fail.pcap"
	oc, _ := json.Marshal(OutputConfigRequest{PcapPath: pcapPath})
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		StrategyIDs: string(sidsJSON), OutputType: "pcap", OutputConfig: string(oc),
		Status: "pending",
	})

	// Deterministically simulate the engine consuming and failing the task
	// in the window between SubmitTask and the old late "running" save.
	// Pre-fix the DB status is still "starting" at this point, so
	// onEngineTaskComplete bails and the late save clobbers the failure —
	// the task wedges in "running" forever. With the fix the "running" save
	// already happened, so the failure is recorded as "failed".
	eid := taskID + "-" + sid
	startSubmitHook = func() {
		e.FailTask(eid, "validation failed: modbus: transaction 0: unsupported function code 0x2A")
	}
	defer func() { startSubmitHook = nil }()

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("start status=%d, body=%s", w.Code, w.Body.String())
	}

	// Wait for the engine to consume and fail the task (worker Plan error
	// path). 5s is generous; the failure fires in milliseconds.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var task storage.TaskModel
		if err := db.Where("id = ?", taskID).First(&task).Error; err != nil {
			t.Fatalf("reload task: %v", err)
		}
		if task.Status != "running" {
			if task.Status != "failed" {
				t.Fatalf("status=%q, error_message=%q", task.Status, task.ErrorMessage)
			}
			if !strings.Contains(task.ErrorMessage, "unsupported function code") {
				t.Fatalf("error_message=%q", task.ErrorMessage)
			}
			return // PASS
		}
		if time.Now().After(deadline) {
			t.Fatalf("task wedged in %q after 5s", task.Status)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
