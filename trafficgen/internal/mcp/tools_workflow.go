package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// generateTrafficInput is the input for flowb_generate_traffic, the one-shot
// "create strategy + create task + start task" workflow.
type generateTrafficInput struct {
	TaskName           string                 `json:"task_name" jsonschema:"task name"`
	Protocol           string                 `json:"protocol" jsonschema:"protocol (tcp/udp/http/dns/icmp/arp)"`
	Config             map[string]interface{} `json:"config" jsonschema:"strategy config (protocol-specific). For tcp/udp/http/dns/icmp/arp -- all fields have defaults, so a minimal {protocol:tcp} works. Defaults applied when absent: src_ip=192.0.2.1 (TEST-NET-1), dst_ip=192.0.2.2, src_port=12345, dst_port=80 (DNS overrides to 53), src_mac=02:00:00:00:00:01, dst_mac=02:00:00:00:00:02, ttl=64, dscp=0x08 (CS1, TOS byte 0x20), ip_flags=DF=1. All overridable; explicit 0/empty/null honored (presence-checked, not zero-defaulted). For http: use an 'http' sub-map {http:{method,uri,version,request_headers,body,body_b64,keep_alive,transactions,think_time,response_headers,response_body,response_body_b64,response_status_code,response_status_text,response_content_encoding,request_content_encoding}}; header defaulting is user>default>none (Host defaults to dst_ip, Connection defaults to keep-alive when transactions>1 or keep_alive=true else close, Content-Length defaults to len(body), Content-Type auto-sniffed from body when absent); response_content_encoding='gzip' compresses response_body, request_content_encoding='gzip' symmetrically compresses request body; body_b64/response_body_b64 base64-encode binary bodies (overrides text Body/ResponseBody). MSS is a TCP transport parameter: set under the 'tcp' sub-map {tcp:{mss,initial_seq,handshake,termination,window_size}} -- mss (default 1460, min 536 per RFC 879) splits request AND response payloads longer than MSS into multiple PSH-ACK TCP segments; legacy 'headers' key still read as fallback for request_headers, and 'flags'/'content_encoding'/'response'/'initial_seq'/'mss' as aliases for the renamed fields. tcpdump filter for trafficgen packets: \"ip[1] & 0xfc == 0x20 or ether host 02:00:00:00:00:01\"."`
	StrategyFlowControl *flowControlInput     `json:"strategy_flow_control,omitempty" jsonschema:"optional strategy-level flow control"`
	TaskFlowControl    *flowControlInput      `json:"task_flow_control,omitempty" jsonschema:"optional task-level flow control (aggregate ceiling)"`
	OutputType         string                 `json:"output_type" jsonschema:"output type: port_group or pcap"`
	OutputConfig       *outputConfigInput     `json:"output_config" jsonschema:"output configuration"`
}

// generateTrafficOutput is the workflow result returned to the LLM.
type generateTrafficOutput struct {
	TaskID     string `json:"task_id"`
	StrategyID string `json:"strategy_id"`
	Status     string `json:"status"`
}

// idResponse is the shape returned by StrategyHandler.Create and
// TaskHandler.Create: {"id": "..."} (optionally with "message" for idempotent hits).
type idResponse struct {
	ID      string `json:"id"`
	Message string `json:"message,omitempty"`
}

func (s *Server) registerWorkflowTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_generate_traffic",
			Description: "One-shot workflow: create strategy + create task + start task. Returns task_id and strategy_id. Most common way to generate traffic.",
		},
		s.handleGenerateTraffic,
	)
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_get_task_progress",
			Description: "Get a task's current progress: status, progress percentage, and live stats (packets_sent, bytes_sent, current_pps, current_bps). Poll this to monitor a running task.",
			OutputSchema: dataOnlyOutputSchema(),
		},
		s.handleGetTaskProgress,
	)
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_stop_all_tasks",
			Description: "Stop all currently running tasks for the service account. Returns list of stopped task IDs and any per-task errors. Tasks already in terminal state are skipped.",
		},
		s.handleStopAllTasks,
	)
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_wait_for_task",
			Description: "Block until a task reaches a terminal state (completed/stopped/error) or timeout. Returns the final task state. Default timeout 60s, max 300s. Use for short tasks; long-running tasks should poll flowb_get_task_progress instead.",
			OutputSchema: dataOnlyOutputSchema(),
		},
		s.handleWaitForTask,
	)
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_replay_pcap",
			Description: "One-shot PCAP replay workflow: create replay strategy + create task + start task. Replays a previously imported PCAP asset with optional speed/rewrite/flow-scaling. Returns task_id and strategy_id.",
		},
		s.handleReplayPcap,
	)
}

func (s *Server) handleGenerateTraffic(ctx context.Context, req *mcp.CallToolRequest, in generateTrafficInput) (*mcp.CallToolResult, generateTrafficOutput, error) {
	start := time.Now()
	stratH := rest.NewStrategyHandler(s.db)
	taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)

	// Step 1: create strategy (mode=synth).
	stratBody := mustMarshal(map[string]interface{}{
		"name":         in.TaskName,
		"mode":         "synth",
		"protocol":     in.Protocol,
		"config":       in.Config,
		"flow_control": in.StrategyFlowControl,
	})
	stratResp, err := s.callHandler(ctx, stratBody, "", nil, stratH.Create)
	if err != nil {
		s.auditLog(req, "flowb_generate_traffic", time.Since(start), "error", "create strategy: "+err.Error())
		return nil, generateTrafficOutput{}, err
	}
	var stratID idResponse
	if err := json.Unmarshal(stratResp.Data, &stratID); err != nil {
		s.auditLog(req, "flowb_generate_traffic", time.Since(start), "error", "parse strategy id: "+err.Error())
		return nil, generateTrafficOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create strategy returned unparseable data: %s", string(stratResp.Data)),
		}
	}
	if stratID.ID == "" {
		s.auditLog(req, "flowb_generate_traffic", time.Since(start), "error", "empty strategy id")
		return nil, generateTrafficOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create strategy returned empty id: %s", string(stratResp.Data)),
		}
	}

	// Step 2: create task referencing the new strategy.
	// On failure we return StrategyID + status="strategy_created" so the LLM
	// can retry the task-creation step (or fall back to flowb_manage_tasks
	// action=create with the strategy_id). This matches ReplayPcap's behavior.
	taskBody := mustMarshal(map[string]interface{}{
		"name":          in.TaskName,
		"strategy_ids":  []string{stratID.ID},
		"output_type":   in.OutputType,
		"output_config": in.OutputConfig,
		"flow_control":  in.TaskFlowControl,
	})
	taskResp, err := s.callHandler(ctx, taskBody, "", nil, taskH.Create)
	if err != nil {
		s.auditLog(req, "flowb_generate_traffic", time.Since(start), "error", "create task: "+err.Error())
		return nil, generateTrafficOutput{StrategyID: stratID.ID, Status: "strategy_created"}, err
	}
	var taskID idResponse
	if err := json.Unmarshal(taskResp.Data, &taskID); err != nil {
		s.auditLog(req, "flowb_generate_traffic", time.Since(start), "error", "parse task id: "+err.Error())
		return nil, generateTrafficOutput{StrategyID: stratID.ID, Status: "strategy_created"}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create task returned unparseable data: %s", string(taskResp.Data)),
		}
	}
	if taskID.ID == "" {
		s.auditLog(req, "flowb_generate_traffic", time.Since(start), "error", "empty task id")
		return nil, generateTrafficOutput{StrategyID: stratID.ID, Status: "strategy_created"}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create task returned empty id: %s", string(taskResp.Data)),
		}
	}

	// Step 3: start the task. The REST handler validates strategies, sets up
	// output writers, submits engine tasks, and updates DB status to "running".
	// R-F2 invariant (replay original/multiplier + bps task FC) is enforced
	// inside Start via validateReplayBPSConflict -- synth mode never triggers it.
	// On Start failure we still return task_id+strategy_id (status="created")
	// so the LLM can retry via flowb_manage_tasks(action=start, id=task_id).
	if _, err := s.callHandler(ctx, nil, taskID.ID, nil, taskH.Start); err != nil {
		s.auditLog(req, "flowb_generate_traffic", time.Since(start), "error", "start task: "+err.Error())
		return nil, generateTrafficOutput{
			TaskID:     taskID.ID,
			StrategyID: stratID.ID,
			Status:     "created",
		}, err
	}

	s.auditLog(req, "flowb_generate_traffic", time.Since(start), "success", "")
	return nil, generateTrafficOutput{
		TaskID:     taskID.ID,
		StrategyID: stratID.ID,
		Status:     "running",
	}, nil
}

// getTaskProgressInput is the input for flowb_get_task_progress.
type getTaskProgressInput struct {
	TaskID string `json:"task_id" jsonschema:"task id to query"`
}

// getTaskProgressOutput wraps the raw task JSON. TaskResponse has many fields
// that vary by status, so we return the raw JSON rather than a fixed struct.
type getTaskProgressOutput struct {
	Data interface{} `json:"data"`
}

func (s *Server) handleGetTaskProgress(ctx context.Context, req *mcp.CallToolRequest, in getTaskProgressInput) (*mcp.CallToolResult, getTaskProgressOutput, error) {
	start := time.Now()
	if in.TaskID == "" {
		s.auditLog(req, "flowb_get_task_progress", 0, "error", "missing task_id")
		return nil, getTaskProgressOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "task_id is required"}
	}
	taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)
	resp, err := s.callHandler(ctx, nil, in.TaskID, nil, taskH.Get)
	if err != nil {
		s.auditLog(req, "flowb_get_task_progress", time.Since(start), "error", err.Error())
		return nil, getTaskProgressOutput{}, err
	}
	s.auditLog(req, "flowb_get_task_progress", time.Since(start), "success", "")
	return nil, getTaskProgressOutput{Data: rawData(resp.Data)}, nil
}

// stopAllTasksInput is the input for flowb_stop_all_tasks.
type stopAllTasksInput struct{}

// stopAllTasksResult is the output for flowb_stop_all_tasks.
type stopAllTasksResult struct {
	Stopped []string         `json:"stopped"`
	Errors  []stopTaskError  `json:"errors,omitempty"`
}
type stopTaskError struct {
	TaskID string `json:"task_id"`
	Error  string `json:"error"`
}

func (s *Server) handleStopAllTasks(ctx context.Context, req *mcp.CallToolRequest, in stopAllTasksInput) (*mcp.CallToolResult, stopAllTasksResult, error) {
	start := time.Now()
	taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)

	// List ALL running tasks for this user, paginating through every page.
	// The REST List endpoint caps page size at 100; without pagination a user
	// with >100 running tasks would silently leave tasks un-stopped. We loop
	// pages until a page returns fewer than `size` items (last page) or we've
	// paginated through 100 pages (defensive upper bound = 10,000 tasks).
	const pageSize = 100
	const maxPages = 100
	var allItems []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	for page := 1; page <= maxPages; page++ {
		q := url.Values{}
		q.Set("status", "running")
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("size", fmt.Sprintf("%d", pageSize))
		resp, err := s.callHandler(ctx, nil, "", q, taskH.List)
		if err != nil {
			s.auditLog(req, "flowb_stop_all_tasks", time.Since(start), "error", fmt.Sprintf("list running page %d: %s", page, err.Error()))
			return nil, stopAllTasksResult{}, err
		}
		var pageData struct {
			Items []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(resp.Data, &pageData); err != nil {
			s.auditLog(req, "flowb_stop_all_tasks", time.Since(start), "error", fmt.Sprintf("parse list page %d: %s", page, err.Error()))
			return nil, stopAllTasksResult{}, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: fmt.Sprintf("parse task list page %d: %s", page, err.Error())}
		}
		allItems = append(allItems, pageData.Items...)
		if len(pageData.Items) < pageSize {
			break
		}
	}

	result := stopAllTasksResult{Stopped: []string{}}
	for _, t := range allItems {
		// Stop each running task. callHandler returns an error if the task
		// transitioned out of running between our list and stop (e.g.,
		// completed naturally); record it but continue with the rest.
		if _, err := s.callHandler(ctx, nil, t.ID, nil, taskH.Stop); err != nil {
			result.Errors = append(result.Errors, stopTaskError{TaskID: t.ID, Error: err.Error()})
			continue
		}
		result.Stopped = append(result.Stopped, t.ID)
	}

	s.auditLog(req, "flowb_stop_all_tasks", time.Since(start), "success", fmt.Sprintf("stopped=%d errors=%d", len(result.Stopped), len(result.Errors)))
	return nil, result, nil
}

// waitForTaskInput is the input for flowb_wait_for_task.
type waitForTaskInput struct {
	TaskID              string `json:"task_id" jsonschema:"task id to wait for"`
	TimeoutSeconds      int    `json:"timeout_seconds,omitempty" jsonschema:"max wait time (default 60, max 300)"`
	PollIntervalSeconds int    `json:"poll_interval_seconds,omitempty" jsonschema:"poll interval (default 2, min 1)"`
}

// waitForTaskOutput wraps the final task state JSON.
type waitForTaskOutput struct {
	Data interface{} `json:"data"`
}

func (s *Server) handleWaitForTask(ctx context.Context, req *mcp.CallToolRequest, in waitForTaskInput) (*mcp.CallToolResult, waitForTaskOutput, error) {
	start := time.Now()
	if in.TaskID == "" {
		s.auditLog(req, "flowb_wait_for_task", 0, "error", "missing task_id")
		return nil, waitForTaskOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "task_id is required"}
	}
	timeout := 60
	if in.TimeoutSeconds > 0 {
		timeout = in.TimeoutSeconds
		if timeout > 300 {
			timeout = 300
		}
	}
	interval := 2
	if in.PollIntervalSeconds > 0 {
		interval = in.PollIntervalSeconds
		if interval < 1 {
			interval = 1
		}
	}

	taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		// Check context cancellation (client disconnect) before each poll.
		if ctx.Err() != nil {
			s.auditLog(req, "flowb_wait_for_task", time.Since(start), "error", "context cancelled")
			return nil, waitForTaskOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "context cancelled: " + ctx.Err().Error()}
		}
		resp, err := s.callHandler(ctx, nil, in.TaskID, nil, taskH.Get)
		if err != nil {
			s.auditLog(req, "flowb_wait_for_task", time.Since(start), "error", "get: "+err.Error())
			return nil, waitForTaskOutput{}, err
		}
		var task struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(resp.Data, &task); err != nil {
			s.auditLog(req, "flowb_wait_for_task", time.Since(start), "error", "parse: "+err.Error())
			return nil, waitForTaskOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "parse task: " + err.Error()}
		}
		// Terminal states: completed, stopped, error, failed.
		switch task.Status {
		case "completed", "stopped", "error", "failed":
			s.auditLog(req, "flowb_wait_for_task", time.Since(start), "success", "terminal="+task.Status)
			return nil, waitForTaskOutput{Data: rawData(resp.Data)}, nil
		}
		if time.Now().After(deadline) {
			s.auditLog(req, "flowb_wait_for_task", time.Since(start), "error", "timeout status="+task.Status)
			return nil, waitForTaskOutput{Data: rawData(resp.Data)}, &jsonrpc.Error{
				Code:    jsonrpc.CodeInternalError,
				Message: fmt.Sprintf("timeout after %ds (last status: %s)", timeout, task.Status),
			}
		}
		select {
		case <-ctx.Done():
			s.auditLog(req, "flowb_wait_for_task", time.Since(start), "error", "context cancelled")
			return nil, waitForTaskOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "context cancelled: " + ctx.Err().Error()}
		case <-time.After(time.Duration(interval) * time.Second):
		}
	}
}

// replayPcapInput is the input for flowb_replay_pcap.
type replayPcapInput struct {
	TaskName            string                   `json:"task_name" jsonschema:"task name"`
	PcapAssetID         string                   `json:"pcap_asset_id" jsonschema:"imported pcap asset id to replay"`
	Loop                int                      `json:"loop,omitempty" jsonschema:"loop count (0=infinite)"`
	Speed               map[string]interface{}   `json:"speed" jsonschema:"replay speed {mode: original|multiplier|bps (empty=max), multiplier, bps} -- bps must be a string like '1000' or '1g' (NOT a number, or backend rejects with 'cannot unmarshal number into Go struct field .speed.bps of type string'); pps and max are rejected by validateReplaySpec"`
	Direction           string                   `json:"direction,omitempty" jsonschema:"single|dual (default single)"`
	ChecksumMode        string                   `json:"checksum_mode,omitempty" jsonschema:"recompute|preserve (default recompute)"`
	Rewrites            []map[string]interface{} `json:"rewrites,omitempty" jsonschema:"rewrite rules"`
	FlowScaling         map[string]interface{}   `json:"flow_scaling,omitempty" jsonschema:"optional multi-flow amplification"`
	StrategyFlowControl *flowControlInput        `json:"strategy_flow_control,omitempty" jsonschema:"optional strategy-level flow control (replay only supports type=time)"`
	TaskFlowControl     *flowControlInput        `json:"task_flow_control,omitempty" jsonschema:"optional task-level flow control (aggregate ceiling)"`
	OutputType          string                   `json:"output_type" jsonschema:"output type: port_group or pcap"`
	OutputConfig        *outputConfigInput       `json:"output_config" jsonschema:"output configuration"`
}

func (s *Server) handleReplayPcap(ctx context.Context, req *mcp.CallToolRequest, in replayPcapInput) (*mcp.CallToolResult, generateTrafficOutput, error) {
	start := time.Now()
	if in.PcapAssetID == "" {
		s.auditLog(req, "flowb_replay_pcap", 0, "error", "missing pcap_asset_id")
		return nil, generateTrafficOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "pcap_asset_id is required"}
	}
	stratH := rest.NewStrategyHandler(s.db)
	taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)

	// Step 1: create replay strategy. mode=replay; protocol is informational
	// (the real protocol comes from the pcap). Config is the ReplaySpec JSON.
	replaySpec := map[string]interface{}{
		"pcap_asset_id":  in.PcapAssetID,
		"loop":           in.Loop,
		"speed":          in.Speed,
		"direction":      in.Direction,
		"checksum_mode":  in.ChecksumMode,
		"rewrites":       in.Rewrites,
		"flow_scaling":   in.FlowScaling,
	}
	stratBody := mustMarshal(map[string]interface{}{
		"name":         in.TaskName,
		"mode":         "replay",
		"protocol":     "replay",
		"config":       replaySpec,
		"flow_control": in.StrategyFlowControl,
	})
	stratResp, err := s.callHandler(ctx, stratBody, "", nil, stratH.Create)
	if err != nil {
		s.auditLog(req, "flowb_replay_pcap", time.Since(start), "error", "create strategy: "+err.Error())
		return nil, generateTrafficOutput{}, err
	}
	var stratID idResponse
	if err := json.Unmarshal(stratResp.Data, &stratID); err != nil {
		s.auditLog(req, "flowb_replay_pcap", time.Since(start), "error", "parse strategy id: "+err.Error())
		return nil, generateTrafficOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create strategy returned unparseable data: %s", string(stratResp.Data)),
		}
	}
	if stratID.ID == "" {
		s.auditLog(req, "flowb_replay_pcap", time.Since(start), "error", "empty strategy id")
		return nil, generateTrafficOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create strategy returned empty id: %s", string(stratResp.Data)),
		}
	}

	// Step 2: create task referencing the replay strategy.
	taskBody := mustMarshal(map[string]interface{}{
		"name":          in.TaskName,
		"strategy_ids":  []string{stratID.ID},
		"output_type":   in.OutputType,
		"output_config": in.OutputConfig,
		"flow_control":  in.TaskFlowControl,
	})
	taskResp, err := s.callHandler(ctx, taskBody, "", nil, taskH.Create)
	if err != nil {
		s.auditLog(req, "flowb_replay_pcap", time.Since(start), "error", "create task: "+err.Error())
		return nil, generateTrafficOutput{StrategyID: stratID.ID, Status: "strategy_created"}, err
	}
	var taskID idResponse
	if err := json.Unmarshal(taskResp.Data, &taskID); err != nil {
		s.auditLog(req, "flowb_replay_pcap", time.Since(start), "error", "parse task id: "+err.Error())
		return nil, generateTrafficOutput{StrategyID: stratID.ID}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create task returned unparseable data: %s", string(taskResp.Data)),
		}
	}
	if taskID.ID == "" {
		s.auditLog(req, "flowb_replay_pcap", time.Since(start), "error", "empty task id")
		return nil, generateTrafficOutput{StrategyID: stratID.ID}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("create task returned empty id: %s", string(taskResp.Data)),
		}
	}

	// Step 3: start the task. R-F2 invariant (replay original/multiplier +
	// bps task FC) is enforced inside Start via validateReplayBPSConflict.
	// On Start failure we return task_id+strategy_id (status="created") so
	// the LLM can retry via flowb_manage_tasks(action=start, id=task_id).
	if _, err := s.callHandler(ctx, nil, taskID.ID, nil, taskH.Start); err != nil {
		s.auditLog(req, "flowb_replay_pcap", time.Since(start), "error", "start task: "+err.Error())
		return nil, generateTrafficOutput{
			TaskID:     taskID.ID,
			StrategyID: stratID.ID,
			Status:     "created",
		}, err
	}

	s.auditLog(req, "flowb_replay_pcap", time.Since(start), "success", "")
	return nil, generateTrafficOutput{
		TaskID:     taskID.ID,
		StrategyID: stratID.ID,
		Status:     "running",
	}, nil
}
