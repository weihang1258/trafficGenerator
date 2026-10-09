package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// managePortGroupsInput covers the 4 port group actions: create / list / get / delete.
// 没有自定义 name：组名恒为 port_group_<hash8>（对完整 ports 配置幂等——
// 同配置重提交返回既有组），自定义名会破坏防重复机制，故不暴露该参数。
type managePortGroupsInput struct {
	Action string          `json:"action" jsonschema:"operation: create|list|get|delete"`
	ID     string          `json:"id,omitempty" jsonschema:"port group id (get/delete)"`
	Ports  []portGroupPort `json:"ports,omitempty" jsonschema:"ports in the group (create)"`
}

type portGroupPort struct {
	Interface string `json:"interface" jsonschema:"interface name"`
	Weight    int    `json:"weight,omitempty" jsonschema:"port weight"`
}

type managePortGroupsOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerPortGroupTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_manage_port_groups",
			Description: "Manage port groups: create/list/get/delete. Port groups bind interfaces for traffic output. create is idempotent on the FULL ports config (interface + weight, order-insensitive): resubmitting the identical config returns the EXISTING group (message 'port group already exists'); a different weight means a DIFFERENT group. Groups are always named port_group_<hash8> (server-generated from the ports config — there is no custom naming).",
			OutputSchema: manageOutputSchema(),
		},
		s.handleManagePortGroups,
	)
}

func (s *Server) handleManagePortGroups(ctx context.Context, req *mcp.CallToolRequest, in managePortGroupsInput) (*mcp.CallToolResult, managePortGroupsOutput, error) {
	start := time.Now()
	h := rest.NewPortGroupHandler(s.db)

	var resp *backendResponse
	var err error

	switch in.Action {
	case "create":
		body := mustMarshal(map[string]interface{}{
			"ports": toRestPorts(in.Ports),
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.Create)
	case "list":
		resp, err = s.callHandler(ctx, nil, "", nil, h.List)
	case "get":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Get)
	case "delete":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Delete)
	default:
		s.auditLog(req, "flowb_manage_port_groups", time.Since(start), "error", "invalid action")
		return nil, managePortGroupsOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (want create|list|get|delete)", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		s.auditLog(req, "flowb_manage_port_groups", duration, "error", err.Error())
		return nil, managePortGroupsOutput{}, err
	}

	s.auditLog(req, "flowb_manage_port_groups", duration, "success", "")
	return nil, managePortGroupsOutput{Action: in.Action, Data: rawData(resp.Data)}, nil
}
