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

// outputConfigInput mirrors rest.OutputConfigRequest for tool input, plus
// Ports for auto-creating the port group (MCP-layer only: resolved to a
// port_group_id before forwarding, so REST/schema/engine never see it).
type outputConfigInput struct {
	PortGroupID string          `json:"port_group_id,omitempty" jsonschema:"existing port group id (for output_type=port_group or both). Mutually exclusive with ports — give one, not both."`
	PcapPath    string          `json:"pcap_path,omitempty" jsonschema:"pcap file path (required for output_type=pcap; optional for output_type=both — a shadow path is generated when omitted)"`
	Interface2  string          `json:"interface2,omitempty" jsonschema:"second interface for dual-port replay (port_group/pcap only — not valid with both; may combine with port_group_id or ports)"`
	Ports       []portGroupPort `json:"ports,omitempty" jsonschema:"auto-create the port group from full group params [{interface, weight}] — same shape as flowb_manage_port_groups create. Multi-NIC with weights supported; idempotent (same interfaces+weights reuse the existing group, order-insensitive). Mutually exclusive with port_group_id — give one, not both. Only for output_type=port_group or both."`
}

// resolveOutputConfigPorts implements output_config.ports auto-create: it
// calls the same PortGroupHandler.Create path as flowb_manage_port_groups
// (same sort+hash+lookup, so a manually created group with the same
// ports+weights is reused — there is no separate auto-created kind), then
// digests the input in place (PortGroupID set, Ports cleared) so everything
// downstream sees the classic shape. Returns the group id and whether it was
// an idempotent reuse. A nil/omitted Ports is a no-op; each violation is an
// InvalidParams error and creates nothing.
func (s *Server) resolveOutputConfigPorts(ctx context.Context, outputType string, oc *outputConfigInput) (string, bool, error) {
	if oc == nil || oc.Ports == nil {
		return "", false, nil
	}
	if len(oc.Ports) == 0 {
		return "", false, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "output_config.ports must not be empty"}
	}
	if oc.PortGroupID != "" {
		return "", false, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "output_config.ports and port_group_id are mutually exclusive (give one)"}
	}
	if outputType != "port_group" && outputType != "both" {
		return "", false, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "output_config.ports requires output_type=port_group or both"}
	}
	for i := range oc.Ports {
		if oc.Ports[i].Interface == "" {
			return "", false, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("output_config.ports[%d].interface is required", i)}
		}
	}
	body := mustMarshal(map[string]interface{}{"ports": toRestPorts(oc.Ports)})
	resp, err := s.callHandler(ctx, body, "", nil, rest.NewPortGroupHandler(s.db).Create)
	if err != nil {
		return "", false, err
	}
	var created struct {
		ID      string `json:"id"`
		Message string `json:"message,omitempty"`
	}
	if uerr := json.Unmarshal(resp.Data, &created); uerr != nil {
		return "", false, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: fmt.Sprintf("port group auto-create returned unparseable data: %s", string(resp.Data))}
	}
	if created.ID == "" {
		return "", false, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: fmt.Sprintf("port group auto-create returned empty id: %s", string(resp.Data))}
	}
	oc.PortGroupID = created.ID
	oc.Ports = nil
	// Reuse is reported inside data.message ("port group already exists",
	// rest/port_group_handler.go), not in the envelope message ("success").
	return created.ID, created.Message == "port group already exists", nil
}

// toRestPorts re-encodes MCP ports into rest.PortConfig so the auto-create
// body hashes byte-identically to a manual flowb_manage_port_groups create:
// portGroupPort.Weight has `json:",omitempty"` (weight 0 drops the key),
// PortConfig.Weight has none (always present) — mixing the two shapes would
// fork the hash space (same logical group, different port_group_<hash8>).
func toRestPorts(ports []portGroupPort) []rest.PortConfig {
	out := make([]rest.PortConfig, len(ports))
	for i, p := range ports {
		out[i] = rest.PortConfig{Interface: p.Interface, Weight: p.Weight}
	}
	return out
}

type manageTasksInput struct {
	Action       string                 `json:"action" jsonschema:"operation: create|create_batch|list|get|start|stop|delete|history"`
	ID           string                 `json:"id,omitempty" jsonschema:"task id (for get/start/stop/delete)"`
	Name         string                 `json:"name,omitempty" jsonschema:"task name (for create/create_batch)"`
	StrategyIDs  []string               `json:"strategy_ids,omitempty" jsonschema:"strategy ids (for create)"`
	Batch        map[string]interface{} `json:"batch,omitempty" jsonschema:"batch spec (for create_batch). Each class accepts an optional group_id strategy field. Classes with the same group_id strategy (same pattern + range) bind to one PacketWorker for cross-flow ordering. See manage_strategies tool's Config.group_id for strategy syntax."`
	OutputType   string                 `json:"output_type,omitempty" jsonschema:"output type: port_group, pcap, or both (both sends to the port group AND mirrors to a shadow pcap — wire target via port_group_id or ports, pcap_path optional and auto-generated when omitted; not valid with interface2) (for create/create_batch). Tip: output_config.ports auto-creates the port group (full params, idempotent) instead of passing port_group_id"`
	OutputConfig *outputConfigInput     `json:"output_config,omitempty" jsonschema:"output configuration (for create/create_batch)"`
	FlowControl  *flowControlInput      `json:"flow_control,omitempty" jsonschema:"optional task-level flow control (for create)"`
	Page         int                    `json:"page,omitempty" jsonschema:"page number for list/history; pagination is optional — omit page/size for the FULL result"`
	Size         int                    `json:"size,omitempty" jsonschema:"omit page/size (or size=0) → FULL result; give size to cap a page (max 100) and page to navigate — full pulls are safe, over 64 KB auto-exports to a file with a download link"`
	Status       string                 `json:"status,omitempty" jsonschema:"status filter for list/history"`
	NamePrefix   string                 `json:"name_prefix,omitempty" jsonschema:"name prefix filter for list — returns only tasks whose name starts with this literal string (LIKE metacharacters escaped); use it to retrieve your own tasks by naming convention instead of pulling the whole library"`
	SortBy       string                 `json:"sort_by,omitempty" jsonschema:"sort column: created_at|updated_at|name|status|progress"`
	SortOrder    string                 `json:"sort_order,omitempty" jsonschema:"ascending|descending (default descending)"`
	StartTime    int64                  `json:"start_time,omitempty" jsonschema:"history filter: unix seconds"`
	OutputPath   string                 `json:"output_path,omitempty" jsonschema:"optional — force the FULL result into a file instead of returning it inline (large lists, extracts, stream bodies); the response becomes a small receipt {written_to, bytes, export_id, download_url}. Remote (HTTP): give just a file name like 'flows.json' — the server stores it and the receipt carries a ready download_url. Local (stdio): give an absolute path on this host. Without output_path, responses above 64 KB are auto-exported the same way, so huge results never flood the conversation"`
	EndTime      int64                  `json:"end_time,omitempty" jsonschema:"history filter: unix seconds"`
}

type manageTasksOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerTaskTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:         "flowb_manage_tasks",
			Description:  "Manage traffic tasks: create/create_batch/list/get/start/stop/delete/history. Use the 'action' field to select the operation. Task responses carry the pcap artifact reference: download_url plus download_howto (HTTP) or output_config.pcap_path (stdio), and pcap_asset_id once auto-registered.",
			OutputSchema: manageOutputSchema(),
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
		if _, _, rerr := s.resolveOutputConfigPorts(ctx, in.OutputType, in.OutputConfig); rerr != nil {
			s.auditLog(req, "flowb_manage_tasks", time.Since(start), "error", "resolve ports: "+rerr.Error())
			return nil, manageTasksOutput{}, rerr
		}
		body := mustMarshal(map[string]interface{}{
			"name":          in.Name,
			"strategy_ids":  in.StrategyIDs,
			"output_type":   in.OutputType,
			"output_config": in.OutputConfig,
			"flow_control":  in.FlowControl,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.Create)
	case "create_batch":
		if _, _, rerr := s.resolveOutputConfigPorts(ctx, in.OutputType, in.OutputConfig); rerr != nil {
			s.auditLog(req, "flowb_manage_tasks", time.Since(start), "error", "resolve ports: "+rerr.Error())
			return nil, manageTasksOutput{}, rerr
		}
		body := mustMarshal(map[string]interface{}{
			"name":          in.Name,
			"batch":         in.Batch,
			"output_type":   in.OutputType,
			"output_config": in.OutputConfig,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.CreateBatch)
	case "list":
		q := buildQuery(map[string]string{
			"page":        fmt.Sprintf("%d", in.Page),
			"size":        fmt.Sprintf("%d", in.Size),
			"status":      in.Status,
			"name_prefix": in.NamePrefix,
			"sort_by":     in.SortBy,
			"sort_order":  in.SortOrder,
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
	if in.OutputPath != "" {
		written, werr := s.applyOutputPath(ctx, in.OutputPath, resp.Data)
		if werr != nil {
			return nil, manageTasksOutput{}, werr
		}
		resp.Data = written
	}
	return nil, manageTasksOutput{Action: in.Action, Data: taskDataForTransport(ctx, s.maybeExport(in.Action, resp.Data))}, nil
}
