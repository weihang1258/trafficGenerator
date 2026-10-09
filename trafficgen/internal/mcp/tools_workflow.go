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
	TaskName            string                 `json:"task_name" jsonschema:"task name"`
	Protocol            string                 `json:"protocol" jsonschema:"protocol name, e.g. modbus/http/dns/a2a — 123 protocols supported; run flowb_query_layers action=examples (no protocol) for the full list"`
	Config              map[string]interface{} `json:"config" jsonschema:"strategy config. layer-chain is the only accepted format (flat config is gone): {\"layers\":[{\"ip\":{\"src\":\"10.0.0.1\",\"dst\":\"20.0.0.1\"}},{\"udp\":{\"dst_port\":53}},{\"dns\":{\"name\":\"a.com\"}}],\"flow_control\":{\"type\":\"flows\",\"value\":1}} — EACH layers element must hold EXACTLY ONE layer key (merging layers into one element, e.g. {\"layers\":[{\"ip\":{...},\"tcp\":{...}}]}, is rejected with 'each layer entry must contain exactly one layer name') — ordered layers, outermost (L2/L3) first; protocol inferred from outermost non-scaffolding layer, explicit protocol must match. Only schema-declared fields accepted: unknown fields rejected (all reported at once), hard depends_on auto-completed. ALWAYS call flowb_query_layers action=examples for the target protocol BEFORE composing a config — it returns verified copy-paste examples (field names like ip.src / http.response_status_code come from there, do not guess); action=schema lists fields/types/defaults/depends_on. Top-level src_ip/dst_ip/src_port/dst_port/count are rejected (flat config is gone). group_id binds same-id flows to one worker, e.g. {\"strategy\":\"fixed\",\"value\":7} | {\"strategy\":\"inc\",\"range\":[1024,2048],\"step\":1} | {\"strategy\":\"rand\",\"range\":[1,254],\"seed\":42} | {\"strategy\":\"list\",\"list\":[3,4]} | {\"strategy\":\"pattern\",\"pattern\":\"host{n}\",\"n_range\":[1,100]} (range is a two-element array [lo,hi])."`
	StrategyFlowControl *flowControlInput      `json:"strategy_flow_control,omitempty" jsonschema:"optional strategy-level flow control — overrides any flow_control embedded in config; omit it to use the config's own (type: flows|bps|time, value > 0)"`
	TaskFlowControl     *flowControlInput      `json:"task_flow_control,omitempty" jsonschema:"optional task-level flow control (aggregate ceiling)"`
	OutputType          string                 `json:"output_type" jsonschema:"output type: port_group, pcap, or both (both = port group + shadow pcap mirror; requires port_group_id, pcap_path optional and auto-generated when omitted; not valid with interface2)"`
	OutputConfig        *outputConfigInput     `json:"output_config" jsonschema:"REQUIRED — for output_type=pcap give {'pcap_path':'/abs/out.pcap'} (remote HTTP: any file name works, the server places it and returns the link); for output_type=port_group give {'port_group_id':'<uuid>'} or {'ports':[{'interface':'<nic-name>','weight':1}]} to auto-create (full group params: multi-NIC with weights supported, idempotent — same ports+weights reuse the existing group; mutually exclusive with port_group_id). NIC output goes through a port group only — list existing groups with flowb_manage_port_groups (action=list)"`
}

// generateTrafficOutput is the workflow result returned to the LLM.
type generateTrafficOutput struct {
	TaskID     string `json:"task_id"`
	StrategyID string `json:"strategy_id"`
	Status     string `json:"status"`
	// PortGroupID/PortGroupReused: echo of the auto-created group when
	// output_config.ports was given (empty otherwise); Reused reports the
	// idempotent hit ("port group already exists") vs a fresh group.
	PortGroupID     string `json:"port_group_id,omitempty"`
	PortGroupReused bool   `json:"port_group_reused,omitempty"`
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
			Description: "One-shot workflow: create strategy + create task + start task. Returns task_id and strategy_id. Most common way to generate traffic. Completed pcap tasks are auto-registered into the asset library (up to 64MB) — flowb_get_task_progress then returns pcap_asset_id, and flowb_manage_pcaps lists/analyzes/downloads the file (list_flows, get_packet, extract).",
		},
		s.handleGenerateTraffic,
	)
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:         "flowb_get_task_progress",
			Description:  "Get a task's current progress: status, progress percentage, and live stats (packets_sent, bytes_sent, current_pps, current_bps). Poll this to monitor a running task. For completed pcap tasks over HTTP the response carries download_url plus download_howto (exact curl instructions to fetch the file unauthenticated); over stdio it carries output_config.pcap_path (local absolute path). Also returns pcap_asset_id once the product is auto-registered into the asset library (<=64MB) — analyze it via flowb_manage_pcaps.",
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
			Name:         "flowb_wait_for_task",
			Description:  "Block until a task reaches a terminal state (completed/stopped/error) or timeout. Returns the final task state — for pcap tasks it includes the artifact reference: download_url plus download_howto (unauthenticated fetch, HTTP) or output_config.pcap_path (stdio), and pcap_asset_id once auto-registered. Default timeout 60s, max 300s. Use for short tasks; long-running tasks should poll flowb_get_task_progress instead.",
			OutputSchema: dataOnlyOutputSchema(),
		},
		s.handleWaitForTask,
	)
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_replay_pcap",
			Description: "One-shot PCAP replay workflow: create replay strategy + create task + start task. Replays a previously imported PCAP asset with optional speed/rewrite/flow-scaling. Returns task_id and strategy_id. Note: replaying the same pcap twice produces byte-identical output, so the content-addressed asset library returns the SAME pcap asset id for both tasks (dedup by design — analyze products by asset id, not by task identity).",
		},
		s.handleReplayPcap,
	)
}

func (s *Server) handleGenerateTraffic(ctx context.Context, req *mcp.CallToolRequest, in generateTrafficInput) (*mcp.CallToolResult, generateTrafficOutput, error) {
	run := s.createAndRunStrategy(ctx, req, "flowb_generate_traffic",
		in.TaskName, in.Protocol, in.Config,
		in.StrategyFlowControl, in.TaskFlowControl,
		in.OutputType, in.OutputConfig)
	if run.Err != nil {
		// createAndRunStrategy already audit-logged each failing step. Preserve
		// the pre-refactor partial-progress semantics: strategy_created vs
		// created vs running.
		status := "strategy_created"
		if run.StrategyID != "" && run.TaskID != "" {
			status = "created"
		}
		return nil, generateTrafficOutput{
			StrategyID: run.StrategyID,
			TaskID:     run.TaskID,
			Status:     status,
		}, run.Err
	}
	return nil, generateTrafficOutput{
		StrategyID:      run.StrategyID,
		TaskID:          run.TaskID,
		Status:          "running",
		PortGroupID:     run.PortGroupID,
		PortGroupReused: run.PortGroupReused,
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
	return nil, getTaskProgressOutput{Data: taskDataForTransport(ctx, resp.Data)}, nil
}

// stopAllTasksInput is the input for flowb_stop_all_tasks.
type stopAllTasksInput struct{}

// stopAllTasksResult is the output for flowb_stop_all_tasks.
type stopAllTasksResult struct {
	Stopped []string        `json:"stopped"`
	Errors  []stopTaskError `json:"errors,omitempty"`
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
			return nil, waitForTaskOutput{Data: taskDataForTransport(ctx, resp.Data)}, nil
		}
		if time.Now().After(deadline) {
			s.auditLog(req, "flowb_wait_for_task", time.Since(start), "error", "timeout status="+task.Status)
			return nil, waitForTaskOutput{Data: taskDataForTransport(ctx, resp.Data)}, &jsonrpc.Error{
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
	Loop                *int                     `json:"loop,omitempty" jsonschema:"loop count — omit for a single pass; 0 = infinite (stop the task to end it); N = N passes"`
	Speed               map[string]interface{}   `json:"speed,omitempty" jsonschema:"optional replay speed {mode: original|multiplier|bps (empty=max), multiplier, bps} -- bps must be a string like '1000' or '1g' (NOT a number, or backend rejects with 'cannot unmarshal number into Go struct field .speed.bps of type string'); pps and max are rejected by validateReplaySpec"`
	Direction           string                   `json:"direction,omitempty" jsonschema:"single|dual (default single)"`
	ChecksumMode        string                   `json:"checksum_mode,omitempty" jsonschema:"recompute|preserve (default recompute)"`
	Rewrites            []map[string]interface{} `json:"rewrites,omitempty" jsonschema:"rewrite rules"`
	FlowScaling         map[string]interface{}   `json:"flow_scaling,omitempty" jsonschema:"optional multi-flow amplification"`
	StrategyFlowControl *flowControlInput        `json:"strategy_flow_control,omitempty" jsonschema:"optional strategy-level flow control (replay only supports type=time)"`
	TaskFlowControl     *flowControlInput        `json:"task_flow_control,omitempty" jsonschema:"optional task-level flow control (aggregate ceiling)"`
	OutputType          string                   `json:"output_type,omitempty" jsonschema:"output type: port_group, pcap, or both (default pcap; both = port group + shadow pcap mirror, requires port_group_id, not valid with interface2)"`
	OutputConfig        *outputConfigInput       `json:"output_config" jsonschema:"REQUIRED — replay: {'pcap_path':'<asset-relative-or-abs>'} or as required by the replay output type; dual-port replay adds {'interface2':'<iface>'}; port_group output may give {'ports':[...]} to auto-create the group (same rule as flowb_generate_traffic)"`
}

func (s *Server) handleReplayPcap(ctx context.Context, req *mcp.CallToolRequest, in replayPcapInput) (*mcp.CallToolResult, generateTrafficOutput, error) {
	start := time.Now()
	if in.PcapAssetID == "" {
		s.auditLog(req, "flowb_replay_pcap", 0, "error", "missing pcap_asset_id")
		return nil, generateTrafficOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "pcap_asset_id is required"}
	}
	if in.OutputType == "" {
		in.OutputType = "pcap" // schema 放宽 required 后的 handler 兜底默认
	}
	stratH := rest.NewStrategyHandler(s.db)
	taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)

	// Step 1: create replay strategy. mode=replay; protocol is informational
	// (the real protocol comes from the pcap). Config is the ReplaySpec JSON.
	// Explicit null is not absence: unset optionals are omitted so the
	// schema sees a missing key (engine default) instead of a null value.
	replaySpec := map[string]interface{}{
		"pcap_asset_id": in.PcapAssetID,
	}
	if in.Loop != nil {
		replaySpec["loop"] = *in.Loop
	}
	if in.Speed != nil {
		replaySpec["speed"] = in.Speed
	}
	if in.Direction != "" {
		replaySpec["direction"] = in.Direction
	}
	if in.ChecksumMode != "" {
		replaySpec["checksum_mode"] = in.ChecksumMode
	}
	if in.Rewrites != nil {
		replaySpec["rewrites"] = in.Rewrites
	}
	if in.FlowScaling != nil {
		replaySpec["flow_scaling"] = in.FlowScaling
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

	// Step 2: create task referencing the replay strategy. Ports (if any)
	// resolve first — same no-rollback rule as createStrategyAndTask.
	var pgID string
	var pgReused bool
	if id, reused, rerr := s.resolveOutputConfigPorts(ctx, in.OutputType, in.OutputConfig); rerr != nil {
		s.auditLog(req, "flowb_replay_pcap", time.Since(start), "error", "resolve ports: "+rerr.Error())
		return nil, generateTrafficOutput{StrategyID: stratID.ID, Status: "strategy_created"}, rerr
	} else {
		pgID, pgReused = id, reused
	}
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
	// bps task FC) is enforced inside Start via schema.ValidateTaskCreate.
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
		TaskID:          taskID.ID,
		StrategyID:      stratID.ID,
		Status:          "running",
		PortGroupID:     pgID,
		PortGroupReused: pgReused,
	}, nil
}
