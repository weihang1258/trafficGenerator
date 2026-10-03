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

// flowControlInput mirrors rest.FlowControlRequest for tool input.
type flowControlInput struct {
	Type  string  `json:"type" jsonschema:"flow control type: flows, bps, or time"`
	Value float64 `json:"value" jsonschema:"flow control value (flow count, bps, or seconds)"`
}

type manageStrategiesInput struct {
	Action      string                 `json:"action" jsonschema:"operation: create|list|get|update|delete|list_tasks"`
	ID          string                 `json:"id,omitempty" jsonschema:"strategy id (for get/update/delete/list_tasks)"`
	Name        string                 `json:"name,omitempty" jsonschema:"strategy name (for create/update)"`
	Mode        string                 `json:"mode,omitempty" jsonschema:"synth or replay (default synth)"`
	Protocol    string                 `json:"protocol,omitempty" jsonschema:"protocol name (for synth); 123 protocols supported — see flowb_query_layers"`
	Config      map[string]interface{} `json:"config,omitempty" jsonschema:"strategy config. layer-chain is the only accepted format (flat config is gone): {\"layers\":[{\"ip\":{\"src\":\"10.0.0.1\",\"dst\":\"20.0.0.1\"}},{\"udp\":{\"dst_port\":53}},{\"dns\":{\"name\":\"a.com\"}}],\"flow_control\":{\"type\":\"flows\",\"value\":1}} — ordered layers, outermost (L2/L3) first; protocol inferred from outermost non-scaffolding layer, explicit protocol must match. Only schema-declared fields accepted: unknown fields rejected (all reported at once), hard depends_on auto-completed. ALWAYS call flowb_query_layers action=examples for the target protocol BEFORE composing a config — it returns verified copy-paste examples (field names like ip.src / http.response_status_code come from there, do not guess); action=schema lists fields/types/defaults/depends_on. Top-level src_ip/dst_ip/src_port/dst_port/count are rejected (flat config is gone). group_id {strategy,value/range/list/step/seed/pattern}: fixed/inc/rand/pattern/list bind same-id flows to one worker."`
	FlowControl *flowControlInput      `json:"flow_control,omitempty" jsonschema:"optional strategy-level flow control"`
}

type manageStrategiesOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerStrategyTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:         "flowb_manage_strategies",
			Description:  "Manage traffic strategies: create/list/get/update/delete/list_tasks. Use the 'action' field to select the operation.",
			OutputSchema: manageOutputSchema(),
		},
		s.handleManageStrategies,
	)
}

func (s *Server) handleManageStrategies(ctx context.Context, req *mcp.CallToolRequest, in manageStrategiesInput) (*mcp.CallToolResult, manageStrategiesOutput, error) {
	start := time.Now()
	h := rest.NewStrategyHandler(s.db)

	var resp *backendResponse
	var err error

	switch in.Action {
	case "create":
		body := mustMarshal(map[string]interface{}{
			"name":         in.Name,
			"mode":         in.Mode,
			"protocol":     in.Protocol,
			"config":       in.Config,
			"flow_control": in.FlowControl,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.Create)
	case "list":
		resp, err = s.callHandler(ctx, nil, "", nil, h.List)
	case "get":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Get)
	case "update":
		body := mustMarshal(map[string]interface{}{
			"name":         in.Name,
			"mode":         in.Mode,
			"protocol":     in.Protocol,
			"config":       in.Config,
			"flow_control": in.FlowControl,
		})
		resp, err = s.callHandler(ctx, body, in.ID, nil, h.Update)
	case "delete":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Delete)
	case "list_tasks":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.ListTasks)
	default:
		s.auditLog(req, "flowb_manage_strategies", time.Since(start), "error", "invalid action")
		return nil, manageStrategiesOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (want create|list|get|update|delete|list_tasks)", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		s.auditLog(req, "flowb_manage_strategies", duration, "error", err.Error())
		return nil, manageStrategiesOutput{}, err
	}

	s.auditLog(req, "flowb_manage_strategies", duration, "success", "")
	return nil, manageStrategiesOutput{Action: in.Action, Data: rawData(resp.Data)}, nil
}

// mustMarshal is a convenience that never fails for map[string]interface{}
// built from struct fields (all values are JSON-serializable).
func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// buildQuery constructs url.Values from a map for callHandler's query param.
func buildQuery(params map[string]string) url.Values {
	if len(params) == 0 {
		return nil
	}
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	return q
}
