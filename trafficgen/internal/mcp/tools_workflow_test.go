package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/replay"
)

// ---------------------------------------------------------------------------
// flowb_get_task_progress
// ---------------------------------------------------------------------------

func TestMCP_GetTaskProgress_HappyPath(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Generate a task first
	_, genOut, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "progress-test",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"dst_port": 80, "count": 3},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/progress.pcap",
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Query progress
	_, out, err := env.srv.handleGetTaskProgress(context.Background(), nil, getTaskProgressInput{
		TaskID: genOut.TaskID,
	})
	if err != nil {
		t.Fatalf("get_task_progress: %v", err)
	}
	var task map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &task); err != nil {
		t.Fatalf("progress returned non-object: %s", string(asRaw(out.Data)))
	}
	if task["id"] != genOut.TaskID {
		t.Errorf("progress.id: got %v, want %s", task["id"], genOut.TaskID)
	}
	status, _ := task["status"].(string)
	if status == "" {
		t.Error("progress.status is empty")
	}
}

func TestMCP_GetTaskProgress_MissingTaskID(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleGetTaskProgress(context.Background(), nil, getTaskProgressInput{})
	if err == nil {
		t.Fatal("expected error for missing task_id, got nil")
	}
}

func TestMCP_GetTaskProgress_NotFound(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleGetTaskProgress(context.Background(), nil, getTaskProgressInput{
		TaskID: "nonexistent-id",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent task, got nil")
	}
}

// ---------------------------------------------------------------------------
// flowb_stop_all_tasks
// ---------------------------------------------------------------------------

func TestMCP_StopAllTasks_NoRunningTasks(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleStopAllTasks(context.Background(), nil, stopAllTasksInput{})
	if err != nil {
		t.Fatalf("stop_all_tasks: %v", err)
	}
	if len(out.Stopped) != 0 {
		t.Errorf("stopped: got %d, want 0", len(out.Stopped))
	}
}

func TestMCP_StopAllTasks_StopsRunningTask(t *testing.T) {
	// Use a slow planner so the task is still running when we stop it
	env := setupMCPTestWithPlanner(t, &slowMCPPlanner{name: "tcp", delay: 50 * time.Millisecond})
	defer env.cleanup()

	_, genOut, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "stop-test",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"dst_port": 80, "count": 10000},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/stop.pcap",
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Give the task a moment to enter running state
	time.Sleep(100 * time.Millisecond)

	_, out, err := env.srv.handleStopAllTasks(context.Background(), nil, stopAllTasksInput{})
	if err != nil {
		t.Fatalf("stop_all_tasks: %v", err)
	}
	if len(out.Stopped) == 0 {
		t.Fatal("expected at least 1 stopped task, got 0")
	}
	found := false
	for _, id := range out.Stopped {
		if id == genOut.TaskID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("generated task %s not in stopped list: %v", genOut.TaskID, out.Stopped)
	}
}

// ---------------------------------------------------------------------------
// flowb_wait_for_task
// ---------------------------------------------------------------------------

func TestMCP_WaitForTask_Completes(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, genOut, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "wait-test",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"dst_port": 80, "count": 3},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/wait.pcap",
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Wait for engine completion. The test env's engine callback signals
	// env.done but does NOT update the DB (MCP uses registerCallbacks=false).
	// We manually update the DB to "completed" to simulate what the REST
	// callback does in production (same pattern as TestMCP_GenerateTraffic_
	// PcapSideEffect at line ~930).
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete")
	}
	env.db.Exec("UPDATE tasks SET status = ?, progress = 100 WHERE id = ?",
		"completed", genOut.TaskID)

	// Now WaitForTask should immediately see "completed" and return.
	_, out, err := env.srv.handleWaitForTask(context.Background(), nil, waitForTaskInput{
		TaskID:              genOut.TaskID,
		TimeoutSeconds:      5,
		PollIntervalSeconds: 1,
	})
	if err != nil {
		t.Fatalf("wait_for_task: %v", err)
	}
	var task map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &task); err != nil {
		t.Fatalf("wait returned non-object: %s", string(asRaw(out.Data)))
	}
	status, _ := task["status"].(string)
	if status != "completed" {
		t.Errorf("expected completed, got %q", status)
	}
}

func TestMCP_WaitForTask_MissingTaskID(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleWaitForTask(context.Background(), nil, waitForTaskInput{})
	if err == nil {
		t.Fatal("expected error for missing task_id, got nil")
	}
}

func TestMCP_WaitForTask_Timeout(t *testing.T) {
	// Use a slow planner so the task is still running when we time out
	env := setupMCPTestWithPlanner(t, &slowMCPPlanner{name: "tcp", delay: 50 * time.Millisecond})
	defer env.cleanup()

	_, genOut, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "timeout-test",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"dst_port": 80, "count": 10000},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/timeout.pcap",
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Wait with a very short timeout - should time out while task is still running
	_, _, err = env.srv.handleWaitForTask(context.Background(), nil, waitForTaskInput{
		TaskID:              genOut.TaskID,
		TimeoutSeconds:      2,
		PollIntervalSeconds: 1,
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// ---------------------------------------------------------------------------
// flowb_replay_pcap
// ---------------------------------------------------------------------------

func TestMCP_ReplayPcap_MissingAssetID(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleReplayPcap(context.Background(), nil, replayPcapInput{
		TaskName: "replay-test",
	})
	if err == nil {
		t.Fatal("expected error for missing pcap_asset_id, got nil")
	}
}

func TestMCP_ReplayPcap_InvalidAssetID(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleReplayPcap(context.Background(), nil, replayPcapInput{
		TaskName:    "replay-test",
		PcapAssetID: "nonexistent-asset",
		Speed:       map[string]interface{}{"mode": "max"},
		OutputType:  "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/replay.pcap",
		},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent pcap_asset_id, got nil")
	}
}

func TestMCP_ReplayPcap_CreatesStrategyAndTask(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Import a pcap first to get a valid asset ID
	assetID := importTestPcap(t, env)

	// Register the replay planner so Start has a chance to work. If Start
	// still fails (e.g., build func mismatch), the tool returns status="created"
	// with the strategy_id + task_id, which is what we're verifying.
	env.eng.SetReplayPlanner(replay.NewReplayPlanner(env.db))

	_, out, err := env.srv.handleReplayPcap(context.Background(), nil, replayPcapInput{
		TaskName:    "replay-test",
		PcapAssetID: assetID,
		Speed:       map[string]interface{}{"mode": "original"},
		Loop:        1,
		OutputType:  "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/replay.pcap",
		},
	})

	// The tool returns (output, error). On Start failure, both are set:
	// output has strategy_id + task_id (status="created"), error has the
	// Start failure. Either path is acceptable for this test.
	// output has strategy_id + task_id (status="created"), error has the
	// Start failure. Either path is acceptable for this test.
	if out.StrategyID == "" {
		t.Fatalf("missing strategy_id (err=%v)", err)
	}
	if out.TaskID == "" {
		t.Fatalf("missing task_id (err=%v)", err)
	}
	if out.Status != "running" && out.Status != "created" {
		t.Errorf("status: got %q, want running or created", out.Status)
	}

	// Verify the strategy was created in replay mode
	_, stratOut, stratErr := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     out.StrategyID,
	})
	if stratErr != nil {
		t.Fatalf("get strategy: %v", stratErr)
	}
	var strat map[string]interface{}
	if err := json.Unmarshal(asRaw(stratOut.Data), &strat); err != nil {
		t.Fatalf("strategy get returned non-object: %s", string(asRaw(stratOut.Data)))
	}
	if strat["mode"] != "replay" {
		t.Errorf("strategy mode: got %v, want replay", strat["mode"])
	}
}
