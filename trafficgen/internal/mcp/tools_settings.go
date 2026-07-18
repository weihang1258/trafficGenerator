package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// manageSettingsInput covers the 2 settings actions: get / update.
// Settings are global (no user_id isolation); service account can read/write.
type manageSettingsInput struct {
	Action     string `json:"action" jsonschema:"operation: get|update"`
	MaxTasks   int    `json:"max_tasks,omitempty" jsonschema:"max concurrent tasks (update; applies immediately)"`
	BufferSize int    `json:"buffer_size,omitempty" jsonschema:"ring buffer size (update; applies on next engine restart)"`
	LogLevel   string `json:"log_level,omitempty" jsonschema:"log level: debug|info|warn|error (update; applies immediately)"`
}

type manageSettingsOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerSettingsTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_manage_settings",
			Description: "Manage system settings: get/update max_tasks, buffer_size, log_level. Settings are global.",
		},
		s.handleManageSettings,
	)
}

func (s *Server) handleManageSettings(ctx context.Context, req *mcp.CallToolRequest, in manageSettingsInput) (*mcp.CallToolResult, manageSettingsOutput, error) {
	start := time.Now()
	h := rest.NewSettingsHandler(s.db, s.engine)

	var resp *backendResponse
	var err error

	switch in.Action {
	case "get":
		resp, err = s.callHandler(ctx, nil, "", nil, h.Get)
	case "update":
		body := mustMarshal(map[string]interface{}{
			"max_tasks":   in.MaxTasks,
			"buffer_size": in.BufferSize,
			"log_level":   in.LogLevel,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.Update)
	default:
		s.auditLog(req, "flowb_manage_settings", time.Since(start), "error", "invalid action")
		return nil, manageSettingsOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (want get|update)", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		s.auditLog(req, "flowb_manage_settings", duration, "error", err.Error())
		return nil, manageSettingsOutput{}, err
	}

	s.auditLog(req, "flowb_manage_settings", duration, "success", "")
	return nil, manageSettingsOutput{Action: in.Action, Data: rawData(resp.Data)}, nil
}
