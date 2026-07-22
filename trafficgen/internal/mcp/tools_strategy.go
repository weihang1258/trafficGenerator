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
	Protocol    string                 `json:"protocol,omitempty" jsonschema:"protocol (for synth, e.g. tcp/udp/http/dns/icmp/arp)"`
	Config      map[string]interface{} `json:"config,omitempty" jsonschema:"strategy config (protocol-specific). For tcp/udp/http/dns/icmp/arp -- all fields have defaults, so a minimal {protocol:tcp} works. Defaults applied when absent: src_ip=192.0.2.1 (TEST-NET-1), dst_ip=192.0.2.2, src_port=12345, dst_port=80 (DNS overrides to 53), src_mac=02:00:00:00:00:01, dst_mac=02:00:00:00:00:02, ttl=64, dscp=0x08 (CS1, TOS byte 0x20), ip_flags=DF=1. All overridable; explicit 0/empty/null honored (presence-checked). For http: use an 'http' sub-map {http:{method,uri,version,request_headers,body,body_b64,keep_alive,transactions,think_time,response_headers,response_body,response_body_b64,response_status_code,response_status_text,response_content_encoding,request_content_encoding}} -- every header field follows user>default>none: user-provided request_headers/response_headers win over derived defaults (Host defaults to dst_ip, Connection defaults to keep-alive when transactions>1 or keep_alive=true else close, Content-Length defaults to len(body)); Content-Type auto-sniffed from body when absent (HTML/XML/JSON/text for text bodies, magic bytes for binary). response_body empty -> no Content-Type/Content-Length defaults. response_content_encoding='gzip' compresses response_body (Content-Length reflects compressed bytes; Content-Encoding header emitted, overridable via response_headers). request_content_encoding='gzip' symmetrically compresses body (request side). body_b64/response_body_b64: base64-encoded binary body (overrides text Body/ResponseBody when set) -- enables sending PNG/ZIP/audio bytes via JSON config. MSS is a TCP transport parameter: set under the 'tcp' sub-map {tcp:{mss,initial_seq,handshake,termination,window_size}} -- mss (default 1460, min 536 per RFC 879) splits request AND response payloads longer than MSS into multiple PSH-ACK TCP segments; SYN/SYN-ACK carry this MSS as a TCP option. initial_seq overrides the random ISN for reproducible tests. Legacy keys still read as fallback: 'flags'->ip_flags, 'content_encoding'->response_content_encoding, 'response'->is_response (UDP/DNS), 'initial_seq' (top-level)->tcp.initial_seq, and 'mss' inside http/ftp/sip sub-maps->tcp.mss. group_id (optional): object {strategy, pattern/value/range/list/step/seed} -- routes flows with the same generated id to one PacketWorker, preserving cross-flow timing (e.g. SIP+RTP). Strategies: fixed/inc/rand/pattern/list. Two classes that should bind must use the same strategy + range. Empty/absent = fall back to 4-tuple unordered hash (single-flow ordering only). tcpdump filter for trafficgen packets: \"ip[1] & 0xfc == 0x20 or ether host 02:00:00:00:00:01\"."`
	FlowControl *flowControlInput      `json:"flow_control,omitempty" jsonschema:"optional strategy-level flow control"`
}

type manageStrategiesOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerStrategyTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_manage_strategies",
			Description: "Manage traffic strategies: create/list/get/update/delete/list_tasks. Use the 'action' field to select the operation.",
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
