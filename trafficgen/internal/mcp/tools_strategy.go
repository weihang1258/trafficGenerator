package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// flowControlInput mirrors rest.FlowControlRequest for tool input.
type flowControlInput struct {
	Type  string  `json:"type" jsonschema:"flow control type: flows, bps, or time at strategy level; packets (stop after N total packets) is task level only"`
	Value float64 `json:"value" jsonschema:"flow control value: flow count / bits per second / seconds / packets — positive; packets must be a whole number"`
}

type manageStrategiesInput struct {
	Description string                 `json:"description" jsonschema:"必填。一句话说明本次调用的目的（将展示给最终用户），不超过 50 字。每次调用必须填写此字段。"`
	Action      string                 `json:"action" jsonschema:"operation: create|list|get|update|delete|list_tasks — update is a FULL replace: it requires config (create-shaped body), not partial fields"`
	ID          string                 `json:"id,omitempty" jsonschema:"strategy id (for get/update/delete/list_tasks)"`
	Name        string                 `json:"name,omitempty" jsonschema:"strategy name (for create/update)"`
	Mode        string                 `json:"mode,omitempty" jsonschema:"synth or replay (default synth)"`
	Protocol    string                 `json:"protocol,omitempty" jsonschema:"protocol name (for synth) — see flowb_query_layers for the full supported list"`
	Config      map[string]interface{} `json:"config,omitempty" jsonschema:"strategy config. layer-chain is the only accepted format (flat config is gone): {\"layers\":[{\"ip\":{\"src\":\"10.0.0.1\",\"dst\":\"20.0.0.1\"}},{\"udp\":{\"dst_port\":53}},{\"dns\":{\"name\":\"a.com\"}}],\"flow_control\":{\"type\":\"flows\",\"value\":1}} — EACH layers element must hold EXACTLY ONE layer key (merging layers into one element, e.g. {\"layers\":[{\"ip\":{...},\"tcp\":{...}}]}, is rejected with 'each layer entry must contain exactly one layer name') — ordered layers, outermost (L2/L3) first, and the chain must END with a terminal (application) layer (a chain ending at a bare transport layer is rejected with 'layer chain must end with a terminal layer'); protocol inferred from outermost non-scaffolding layer, explicit protocol must match. Only schema-declared fields accepted: unknown fields rejected (all reported at once), hard depends_on auto-completed. ALWAYS call flowb_query_layers action=examples for the target protocol BEFORE composing a config — it returns verified copy-paste examples (field names like ip.src / http.response_status_code come from there, do not guess); action=schema lists fields/types/defaults/depends_on. Top-level src_ip/dst_ip/src_port/dst_port/count are rejected (flat config is gone). group_id binds same-id flows to one worker, e.g. {\"strategy\":\"fixed\",\"value\":7} | {\"strategy\":\"inc\",\"range\":[1024,2048],\"step\":1} | {\"strategy\":\"rand\",\"range\":[1,254],\"seed\":42} | {\"strategy\":\"list\",\"list\":[3,4]} | {\"strategy\":\"pattern\",\"pattern\":\"host{n}\",\"n_range\":[1,100]} (range is a two-element array [lo,hi])."`
	FlowControl *flowControlInput      `json:"flow_control,omitempty" jsonschema:"optional strategy-level flow control — overrides any flow_control embedded in config; omit it to use the config's own (type: flows|bps|time, value > 0)"`
	OutputPath  string                 `json:"output_path,omitempty" jsonschema:"optional — force the FULL result into a file instead of returning it inline (large lists, extracts, stream bodies); the response becomes a small receipt {written_to, bytes, export_id, download_url}. Remote (HTTP): give just a file name like 'flows.json' — the server stores it and the receipt carries a ready download_url. Local (stdio): give an absolute path on this host. Without output_path, responses above 64 KB are auto-exported the same way, so huge results never flood the conversation"`
	Page        int                    `json:"page,omitempty" jsonschema:"list only: page number (1-based). size=0 means ALL rows (no LIMIT), same as every other list endpoint; non-numeric or negative size falls back to the default 50"`
	Size        int                    `json:"size,omitempty" jsonschema:"list only: page size, max 1000 (bigger values clamp to 1000). The response is ALWAYS the envelope {items,page,size,total}. Omit page/size for the FULL result, still wrapped in that envelope — size in a full response is the actual row count, not 0, and a full response is not paginated (do not infer more pages from total/size). A page past the end is an empty items array, never an error."`
}

type manageStrategiesOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerStrategyTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:         "flowb_manage_strategies",
			Description:  "Manage traffic strategies: create/list/get/update/delete/list_tasks. Use the 'action' field to select the operation. create is idempotent on name+config: resubmitting the same strategy returns the EXISTING id with message 'strategy already exists' (nothing new is created).",
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
		// R7：MCP 侧放行可选分页（REST strategies/list 批 5 已支持）。
		//
		// size 恒发：REST 的策略列表是"page/size 任一给定才返回分页封装，
		// 否则返回裸数组"，而 size=0 是全量哨兵。MCP 省略 size 时若也不发，
		// `page=2` 会掉进裸数组分支（没有分页字段），与 pcap/task 列表的
		// "省略=全量分页"不一致。发 size=0 才走统一的分页口径。
		q := url.Values{}
		if in.Page > 0 {
			q.Set("page", strconv.Itoa(in.Page))
		}
		if in.Size > 0 {
			q.Set("size", strconv.Itoa(in.Size))
		} else {
			q.Set("size", "0")
		}
		resp, err = s.callHandler(ctx, nil, "", q, h.List)
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
	if in.OutputPath != "" {
		written, werr := s.applyOutputPath(ctx, in.OutputPath, resp.Data)
		if werr != nil {
			return nil, manageStrategiesOutput{}, werr
		}
		resp.Data = written
	}
	return nil, manageStrategiesOutput{Action: in.Action, Data: taskDataForTransport(ctx, s.maybeExport(in.Action, resp.Data))}, nil
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
