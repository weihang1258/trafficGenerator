package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// manageProfileInput covers the 3 profile actions: get / update / delete.
// All operate on the current user (service account in Phase 1).
type manageProfileInput struct {
	Action      string `json:"action" jsonschema:"operation: get|update|delete"`
	Email       string `json:"email,omitempty" jsonschema:"new email (update)"`
	Password    string `json:"password,omitempty" jsonschema:"current password (delete, for confirmation) OR new password (update, min 8 chars)"`
	NewPassword string `json:"new_password,omitempty" jsonschema:"new password (update, min 8 chars; alternative to password field)"`
}

type manageProfileOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerProfileTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_manage_profile",
			Description: "Manage current user's profile: get/update/delete. In service account mode, operates on mcp-service account.",
		},
		s.handleManageProfile,
	)
}

func (s *Server) handleManageProfile(ctx context.Context, req *mcp.CallToolRequest, in manageProfileInput) (*mcp.CallToolResult, manageProfileOutput, error) {
	start := time.Now()
	// Profile methods (GetProfile/UpdateProfile/DeleteProfile) do not use
	// jwtManager -- they read userID from context. nil jwtManager is safe here.
	h := rest.NewAuthHandler(s.db, nil)

	var resp *backendResponse
	var err error

	switch in.Action {
	case "get":
		resp, err = s.callHandler(ctx, nil, "", nil, h.GetProfile)
	case "update":
		// UpdateProfileRequest has email + password fields. The "password"
		// field in the backend means NEW password (not current). We accept
		// either password or new_password from the LLM and map to "password".
		pwd := in.Password
		if in.NewPassword != "" {
			pwd = in.NewPassword
		}
		body := mustMarshal(map[string]interface{}{
			"email":    in.Email,
			"password": pwd,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.UpdateProfile)
	case "delete":
		// DeleteProfile reads password from body for confirmation.
		body := mustMarshal(map[string]interface{}{
			"password": in.Password,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.DeleteProfile)
	default:
		s.auditLog(req, "flowb_manage_profile", time.Since(start), "error", "invalid action")
		return nil, manageProfileOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (want get|update|delete)", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		s.auditLog(req, "flowb_manage_profile", duration, "error", err.Error())
		return nil, manageProfileOutput{}, err
	}

	s.auditLog(req, "flowb_manage_profile", duration, "success", "")
	return nil, manageProfileOutput{Action: in.Action, Data: rawData(resp.Data)}, nil
}
