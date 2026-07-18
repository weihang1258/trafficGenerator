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
type managePortGroupsInput struct {
	Action string            `json:"action" jsonschema:"operation: create|list|get|delete"`
	ID     string            `json:"id,omitempty" jsonschema:"port group id (get/delete)"`
	Name   string            `json:"name,omitempty" jsonschema:"port group name (create)"`
	Ports  []portGroupPort   `json:"ports,omitempty" jsonschema:"ports in the group (create)"`
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
			Description: "Manage port groups: create/list/get/delete. Port groups bind interfaces for traffic output.",
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
			"name":  in.Name,
			"ports": in.Ports,
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
