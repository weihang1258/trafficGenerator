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
//
// 字段约束必须与 REST 侧一致，否则调用方按描述写、按后端被拒（或者反过来，
// 描述说要做确认、后端其实根本不看）：
//   - update: email 需合法（binding:omitempty,email），password 8-128 字符
//   - delete: 不接受密码——后端 DeleteProfile 直接删当前账号，不做二次确认
//   - admin 账号不能经本工具改/删（后端返回 403）
type manageProfileInput struct {
	Description string `json:"description" jsonschema:"必填。一句话说明本次调用的目的（将展示给最终用户），不超过 50 字。每次调用必须填写此字段。"`
	Action      string `json:"action" jsonschema:"operation: get|update|delete (delete removes the CURRENT account immediately — there is no password confirmation; admin accounts cannot be updated or deleted through this tool, both return 403)"`
	Email       string `json:"email,omitempty" jsonschema:"new email (update only). Must be a valid email address; a duplicate email returns 400."`
	Password    string `json:"password,omitempty" jsonschema:"update only: the NEW password, 8-128 characters. Ignored by delete (delete needs no confirmation)."`
	NewPassword string `json:"new_password,omitempty" jsonschema:"update only: same as password, 8-128 characters; alternative spelling. If both are given, new_password wins."`
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
			OutputSchema: manageOutputSchema(),
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
		// DeleteProfile 不读请求体：它按 userID 删当前账号，不做密码确认。
		// 这里原先发送 {"password": ...} 并宣称"用于确认"，其实后端从来没看
		// ——调方以为删错了还能靠密码兜底。现在显式拒绝带密码的删除请求，
		// 把"立即生效、无确认"这个事实摆到调用方面前。
		if in.Password != "" || in.NewPassword != "" {
			s.auditLog(req, "flowb_manage_profile", time.Since(start), "error", "delete takes no password")
			return nil, manageProfileOutput{}, &jsonrpc.Error{
				Code:    jsonrpc.CodeInvalidParams,
				Message: "delete takes no password — it removes the current account immediately. Omit password/new_password and call again to confirm.",
			}
		}
		resp, err = s.callHandler(ctx, nil, "", nil, h.DeleteProfile)
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
