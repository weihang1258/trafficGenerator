package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// genRun is the outcome of createAndRunStrategy, shared by
// flowb_generate_traffic and the protocol test tools. It carries the created
// strategy/task ids and, when start succeeded, a true Running flag. When start
// fails, Running is false and the caller decides how to surface the error
// (generate_traffic returns status="created"; the test tools treat it as a
// failed case).
type genRun struct {
	StrategyID string
	TaskID     string
	Running    bool
	Err        error
	// PortGroupID/PortGroupReused: echo of the auto-created group when the
	// caller passed output_config.ports (empty otherwise); Reused reports
	// the idempotent hit vs a fresh group. Carried on genRun (not
	// outputConfigInput) because the pointer is digested in place by
	// resolveOutputConfigPorts before the task create.
	PortGroupID     string
	PortGroupReused bool
}

// createAndRunStrategy drives the 3-step workflow (create strategy -> create
// task -> start task) via the REST handlers. It is the single implementation of
// this flow so flowb_generate_traffic and flowb_run_protocol_case run the same
// code path (CLAUDE.md "所有测试经 MCP 执行").
func (s *Server) createAndRunStrategy(ctx context.Context, req *mcp.CallToolRequest, toolName string,
	taskName, protocol string, config map[string]interface{}, stratFC *flowControlInput,
	taskFC *flowControlInput, outputType string, outputConfig *outputConfigInput) genRun {
	run, taskH := s.createStrategyAndTask(ctx, req, toolName, taskName, protocol, config, stratFC, taskFC, outputType, outputConfig)
	if run.Err != nil {
		s.cleanupCreatedRun(ctx, run)
		return run
	}
	if err := s.startStrategyTask(ctx, req, toolName, taskH, run.TaskID); err != nil {
		s.cleanupCreatedRun(ctx, run)
		return genRun{StrategyID: run.StrategyID, TaskID: run.TaskID, PortGroupID: run.PortGroupID, PortGroupReused: run.PortGroupReused, Err: err}
	}
	return genRun{StrategyID: run.StrategyID, TaskID: run.TaskID, PortGroupID: run.PortGroupID, PortGroupReused: run.PortGroupReused, Running: true}
}

func (s *Server) createStrategyAndTask(ctx context.Context, req *mcp.CallToolRequest, toolName string,
	taskName, protocol string, config map[string]interface{}, stratFC *flowControlInput,
	taskFC *flowControlInput, outputType string, outputConfig *outputConfigInput) (genRun, *rest.TaskHandler) {
	stratH := rest.NewStrategyHandler(s.db)
	taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)
	start := time.Now()

	// Step 1: create strategy (mode=synth). Failure returns early without a
	// strategy id; the caller maps it to an MCP error.
	stratBody := mustMarshal(map[string]interface{}{
		"name":         taskName,
		"mode":         "synth",
		"protocol":     protocol,
		"config":       config,
		"flow_control": stratFC,
	})
	stratResp, err := s.callHandler(ctx, stratBody, "", nil, stratH.Create)
	if err != nil {
		s.auditLog(req, toolName, time.Since(start), "error", "create strategy: "+err.Error())
		return genRun{Err: err}, taskH
	}
	var stratID idResponse
	if err := json.Unmarshal(stratResp.Data, &stratID); err != nil {
		s.auditLog(req, toolName, time.Since(start), "error", "parse strategy id: "+err.Error())
		return genRun{Err: &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create strategy returned unparseable data: %s", string(stratResp.Data)),
		}}, taskH
	}
	if stratID.ID == "" {
		s.auditLog(req, toolName, time.Since(start), "error", "empty strategy id")
		return genRun{Err: &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create strategy returned empty id: %s", string(stratResp.Data)),
		}}, taskH
	}

	// Step 2: create task. Ports (if any) are resolved to a port_group_id
	// BEFORE this step: the strategy is already created, so its cleanup is
	// the caller's; the auto-created group is explicitly NOT rolled back
	// (it is a first-class entry, reusable by later calls).
	var pgID string
	var pgReused bool
	if id, reused, rerr := s.resolveOutputConfigPorts(ctx, outputType, outputConfig); rerr != nil {
		s.auditLog(req, toolName, time.Since(start), "error", "resolve ports: "+rerr.Error())
		return genRun{StrategyID: stratID.ID, Err: rerr}, taskH
	} else {
		pgID, pgReused = id, reused
	}
	taskBody := mustMarshal(map[string]interface{}{
		"name":          taskName,
		"strategy_ids":  []string{stratID.ID},
		"output_type":   outputType,
		"output_config": outputConfig,
		"flow_control":  taskFC,
	})
	taskResp, err := s.callHandler(ctx, taskBody, "", nil, taskH.Create)
	if err != nil {
		s.auditLog(req, toolName, time.Since(start), "error", "create task: "+err.Error())
		return genRun{StrategyID: stratID.ID, PortGroupID: pgID, PortGroupReused: pgReused, Err: err}, taskH
	}
	var taskID idResponse
	if err := json.Unmarshal(taskResp.Data, &taskID); err != nil {
		s.auditLog(req, toolName, time.Since(start), "error", "parse task id: "+err.Error())
		return genRun{StrategyID: stratID.ID, PortGroupID: pgID, PortGroupReused: pgReused, Err: &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create task returned unparseable data: %s", string(taskResp.Data)),
		}}, taskH
	}
	if taskID.ID == "" {
		s.auditLog(req, toolName, time.Since(start), "error", "empty task id")
		return genRun{StrategyID: stratID.ID, PortGroupID: pgID, PortGroupReused: pgReused, Err: &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create task returned empty id: %s", string(taskResp.Data)),
		}}, taskH
	}

	// Task creation is complete; the caller controls when Start runs so NIC
	// capture can be armed before traffic begins.
	return genRun{StrategyID: stratID.ID, TaskID: taskID.ID, PortGroupID: pgID, PortGroupReused: pgReused}, taskH
}

func (s *Server) startStrategyTask(ctx context.Context, req *mcp.CallToolRequest, toolName string, taskH *rest.TaskHandler, taskID string) error {
	if _, err := s.callHandler(ctx, nil, taskID, nil, taskH.Start); err != nil {
		s.auditLog(req, toolName, 0, "error", "start task: "+err.Error())
		return err
	}
	s.auditLog(req, toolName, 0, "success", "")
	return nil
}

// waitForTaskTerminal polls flowb task.Get until the task reaches a terminal
// state (completed/stopped/error/failed) or the deadline passes. It returns the
// task status string and its error message (empty when the task succeeded).
// The ctx deadline governs the wait; context cancellation aborts immediately.
//
// The DB status only reaches a terminal state when the REST server's
// onEngineTaskComplete callback updated it, so callers must run with REST
// callbacks registered (production) or an equivalent test-env that registers
// them (setupTestDriveEnv does this). It does NOT mutate engine hook fields,
// so it is safe to call concurrently (parallel suites).
func (s *Server) waitForTaskTerminal(ctx context.Context, taskID string, deadline time.Time) (status, errMsg string, err error) {
	taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)
	for {
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		resp, err := s.callHandler(ctx, nil, taskID, nil, taskH.Get)
		if err != nil {
			return "", "", err
		}
		var task struct {
			Status       string `json:"status"`
			ErrorMessage string `json:"error_message,omitempty"`
		}
		if err := json.Unmarshal(resp.Data, &task); err != nil {
			return "", "", err
		}
		switch task.Status {
		case "completed", "stopped", "error", "failed":
			return task.Status, task.ErrorMessage, nil
		}
		if time.Now().After(deadline) {
			return task.Status, "", fmt.Errorf("task %s not terminal after deadline (status=%s)", taskID, task.Status)
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// getTaskStats returns the live packet/byte counters from a task's Get
// payload. packet_count / byte_count are updated by the engine as packets are
// written.
func getTaskStats(resp *backendResponse) (int64, int64) {
	var task struct {
		PacketCount int64 `json:"packet_count"`
		ByteCount   int64 `json:"byte_count"`
	}
	if err := json.Unmarshal(resp.Data, &task); err != nil {
		return 0, 0
	}
	return task.PacketCount, task.ByteCount
}
