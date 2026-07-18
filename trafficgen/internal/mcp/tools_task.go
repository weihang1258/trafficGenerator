package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// outputConfigInput mirrors rest.OutputConfigRequest for tool input.
type outputConfigInput struct {
	PortGroupID string `json:"port_group_id,omitempty" jsonschema:"port group id (for output_type=port_group)"`
	PcapPath    string `json:"pcap_path,omitempty" jsonschema:"pcap file path (for output_type=pcap)"`
	Interface2  string `json:"interface2,omitempty" jsonschema:"second interface for dual-port replay"`
}

type manageTasksInput struct {
	Action       string                 `json:"action" jsonschema:"operation: create|create_batch|list|get|start|stop|delete|history"`
	ID           string                 `json:"id,omitempty" jsonschema:"task id (for get/start/stop/delete)"`
	Name         string                 `json:"name,omitempty" jsonschema:"task name (for create/create_batch)"`
	StrategyIDs  []string               `json:"strategy_ids,omitempty" jsonschema:"strategy ids (for create)"`
	Batch        map[string]interface{} `json:"batch,omitempty" jsonschema:"batch spec (for create_batch). Each class accepts an optional group_id strategy field. Classes with the same group_id strategy (same pattern + range) bind to one PacketWorker for cross-flow ordering. See manage_strategies tool's Config.group_id for strategy syntax."`
	OutputType   string                 `json:"output_type,omitempty" jsonschema:"output type: port_group or pcap (for create/create_batch)"`
	OutputConfig *outputConfigInput     `json:"output_config,omitempty" jsonschema:"output configuration (for create/create_batch)"`
	FlowControl  *flowControlInput      `json:"flow_control,omitempty" jsonschema:"optional task-level flow control (for create)"`
	Page         int                    `json:"page,omitempty" jsonschema:"page number for list/history (1-based)"`
	Size         int                    `json:"size,omitempty" jsonschema:"page size for list/history (default 20, max 100)"`
	Status       string                 `json:"status,omitempty" jsonschema:"status filter for list/history"`
	SortBy       string                 `json:"sort_by,omitempty" jsonschema:"sort column: created_at|updated_at|name|status|progress"`
	SortOrder    string                 `json:"sort_order,omitempty" jsonschema:"ascending|descending (default descending)"`
	StartTime    int64                  `json:"start_time,omitempty" jsonschema:"history filter: unix seconds"`
	EndTime      int64                  `json:"end_time,omitempty" jsonschema:"history filter: unix seconds"`
}

type manageTasksOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerTaskTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_manage_tasks",
			Description: "Manage traffic tasks: create/create_batch/list/get/start/stop/delete/history. Use the 'action' field to select the operation.",
		},
		s.handleManageTasks,
	)
}

func (s *Server) handleManageTasks(ctx context.Context, req *mcp.CallToolRequest, in manageTasksInput) (*mcp.CallToolResult, manageTasksOutput, error) {
	start := time.Now()
	// MCP's TaskHandler must NOT register engine callbacks -- the REST server
	// owns those (OnTaskComplete/OnTaskFailed/OnOutputError/OnProgress) so
	// WebSocket push and DB status updates continue to flow through the REST
	// path. MCP just invokes handler methods directly.
	h := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)

	var resp *backendResponse
	var err error

	switch in.Action {
	case "create":
		body := mustMarshal(map[string]interface{}{
			"name":          in.Name,
			"strategy_ids":  in.StrategyIDs,
			"output_type":   in.OutputType,
			"output_config": in.OutputConfig,
			"flow_control":  in.FlowControl,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.Create)
	case "create_batch":
		body := mustMarshal(map[string]interface{}{
			"name":          in.Name,
			"batch":         in.Batch,
			"output_type":   in.OutputType,
			"output_config": in.OutputConfig,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.CreateBatch)
	case "list":
		q := buildQuery(map[string]string{
			"page":       fmt.Sprintf("%d", in.Page),
			"size":       fmt.Sprintf("%d", in.Size),
			"status":     in.Status,
			"sort_by":    in.SortBy,
			"sort_order": in.SortOrder,
		})
		resp, err = s.callHandler(ctx, nil, "", q, h.List)
	case "get":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Get)
	case "start":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Start)
	case "stop":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Stop)
	case "delete":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Delete)
	case "history":
		q := buildQuery(map[string]string{
			"page":       fmt.Sprintf("%d", in.Page),
			"size":       fmt.Sprintf("%d", in.Size),
			"status":     in.Status,
			"sort_by":    in.SortBy,
			"sort_order": in.SortOrder,
			"start_time": fmt.Sprintf("%d", in.StartTime),
			"end_time":   fmt.Sprintf("%d", in.EndTime),
		})
		resp, err = s.callHandler(ctx, nil, "", q, h.History)
	default:
		s.auditLog(req, "flowb_manage_tasks", time.Since(start), "error", "invalid action")
		return nil, manageTasksOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (want create|create_batch|list|get|start|stop|delete|history)", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		s.auditLog(req, "flowb_manage_tasks", duration, "error", err.Error())
		return nil, manageTasksOutput{}, err
	}

	s.auditLog(req, "flowb_manage_tasks", duration, "success", "")
	return nil, manageTasksOutput{Action: in.Action, Data: rawData(resp.Data)}, nil
}
