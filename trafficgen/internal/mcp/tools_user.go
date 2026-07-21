package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// manageUsersInput covers the 5 user admin actions. All map to admin-only
// endpoints; in service account mode (role=user) the backend returns 403.
// The tool is registered anyway so Phase 3 (multi-user/API-key-as-admin)
// unlocks it without code changes.
type manageUsersInput struct {
	Action     string `json:"action" jsonschema:"operation: list|get|update|delete|reset_password"`
	ID         string `json:"id,omitempty" jsonschema:"user id (get/update/delete/reset_password)"`
	Email      string `json:"email,omitempty" jsonschema:"new email (update)"`
	Role       string `json:"role,omitempty" jsonschema:"new role: admin|user|guest (update)"`
	Enabled    *bool  `json:"enabled,omitempty" jsonschema:"new enabled state (update)"`
}

type manageUsersOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerUserTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_manage_users",
			Description: "Manage users (admin only): list/get/update/delete/reset_password. In service account mode, all actions return 403 -- tool exists for Phase 3 multi-user mode.",
			OutputSchema: manageOutputSchema(),
		},
		s.handleManageUsers,
	)
}

func (s *Server) handleManageUsers(ctx context.Context, req *mcp.CallToolRequest, in manageUsersInput) (*mcp.CallToolResult, manageUsersOutput, error) {
	start := time.Now()
	h := rest.NewUserHandler(s.db)

	var resp *backendResponse
	var err error

	switch in.Action {
	case "list":
		resp, err = s.callHandler(ctx, nil, "", nil, h.List)
	case "get":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Get)
	case "update":
		body := mustMarshal(map[string]interface{}{
			"email":   in.Email,
			"role":    in.Role,
			"enabled": in.Enabled,
		})
		resp, err = s.callHandler(ctx, body, in.ID, nil, h.Update)
	case "delete":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Delete)
	case "reset_password":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.ResetPassword)
	default:
		s.auditLog(req, "flowb_manage_users", time.Since(start), "error", "invalid action")
		return nil, manageUsersOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (want list|get|update|delete|reset_password)", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		// In service account mode (role=user), all admin-only actions return
		// an error with message "admin access required" (HTTP 403 -> jsonrpc
		// InvalidParams). This is expected; the LLM sees the message and knows
		// the action requires admin privileges (Phase 3 multi-user mode).
		s.auditLog(req, "flowb_manage_users", duration, "error", err.Error())
		return nil, manageUsersOutput{}, err
	}

	s.auditLog(req, "flowb_manage_users", duration, "success", "")
	return nil, manageUsersOutput{Action: in.Action, Data: rawData(resp.Data)}, nil
}
