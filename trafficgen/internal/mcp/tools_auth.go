package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// manageAuthInput covers the 5 auth actions. register/login are public (no
// token needed). validate/logout/refresh require a JWT token from the LLM;
// MCP parses it to derive the caller identity (NOT the service account).
type manageAuthInput struct {
	Action  string `json:"action" jsonschema:"operation: register|login|validate|logout|refresh"`
	Username string `json:"username,omitempty" jsonschema:"username (register/login)"`
	Password string `json:"password,omitempty" jsonschema:"password (register/login, min 8 chars)"`
	Email   string `json:"email,omitempty" jsonschema:"email (register)"`
	Token   string `json:"token,omitempty" jsonschema:"JWT token (validate/logout/refresh)"`
}

type manageAuthOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerAuthTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_manage_auth",
			Description: "Manage authentication: register/login (public), validate/logout/refresh (need JWT token). Token-based actions derive caller identity from the token, not the service account.",
			OutputSchema: manageOutputSchema(),
		},
		s.handleManageAuth,
	)
}

func (s *Server) handleManageAuth(ctx context.Context, req *mcp.CallToolRequest, in manageAuthInput) (*mcp.CallToolResult, manageAuthOutput, error) {
	start := time.Now()
	h := rest.NewAuthHandler(s.db, s.jwtManager)

	var resp *backendResponse
	var err error

	switch in.Action {
	case "register":
		body := mustMarshal(map[string]interface{}{
			"username": in.Username,
			"password": in.Password,
			"email":    in.Email,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.Register)
	case "login":
		body := mustMarshal(map[string]interface{}{
			"username": in.Username,
			"password": in.Password,
		})
		resp, err = s.callHandler(ctx, body, "", nil, h.Login)
	case "validate":
		resp, err = s.callHandlerWithToken(ctx, nil, in.Token, h.ValidateToken)
	case "logout":
		resp, err = s.callHandlerWithToken(ctx, nil, in.Token, h.Logout)
	case "refresh":
		resp, err = s.callHandlerWithToken(ctx, nil, in.Token, h.Refresh)
	default:
		s.auditLog(req, "flowb_manage_auth", time.Since(start), "error", "invalid action")
		return nil, manageAuthOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (want register|login|validate|logout|refresh)", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		// Passwords/tokens never appear in err.Error() (backend returns generic
		// messages like "invalid credentials"), so safe to log.
		s.auditLog(req, "flowb_manage_auth", duration, "error", err.Error())
		return nil, manageAuthOutput{}, err
	}

	s.auditLog(req, "flowb_manage_auth", duration, "success", "")
	return nil, manageAuthOutput{Action: in.Action, Data: rawData(resp.Data)}, nil
}

// callHandlerWithToken invokes a gin handler with caller identity derived
// from the LLM-provided JWT token (not the service account). Used by auth
// validate/logout/refresh, which need the token's user rather than the
// service account.
//
// The token is parsed (JWT-validated) to extract userID/username/roles,
// which are set in the gin context. The raw token is also passed via the
// Authorization: Bearer header for handlers that read it directly
// (ValidateToken/Logout).
//
// If jwtManager is nil (misconfiguration), returns an InternalError.
// If the token is empty or JWT-invalid, returns InvalidParams.
func (s *Server) callHandlerWithToken(ctx context.Context, body []byte, token string, handler func(*gin.Context)) (resp *backendResponse, err error) {
	if s.jwtManager == nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: "mcp server missing jwt manager (configure mcp.service_account_password and auth.jwt_secret)",
		}
	}
	if token == "" {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: "token is required for this action",
		}
	}

	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: "invalid or expired token: " + err.Error(),
		}
	}

	// Defense-in-depth: verify the token is still active in the DB. The REST
	// AuthMiddlewareWithDB does this check on every authenticated request; MCP
	// bypasses that middleware (we construct gin.Context directly), so we
	// must do it here. A revoked/logged-out token must not be usable for
	// validate/logout/refresh, even if the JWT signature is still valid.
	tokenHash := hashTokenForMCP(token)
	var tokenRecord storage.TokenModel
	if err := s.db.Where("token_hash = ?", tokenHash).First(&tokenRecord).Error; err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: "token not found or revoked",
		}
	}
	if tokenRecord.Status != "active" {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: "token is " + tokenRecord.Status + " (not active)",
		}
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// Override service-account identity with the token's actual user.
	c.Set("userID", claims.UserID)
	c.Set("username", claims.Username)
	c.Set("roles", claims.Roles)

	method := "GET"
	var bodyReader io.Reader
	if body != nil {
		method = "POST"
		bodyReader = bytes.NewReader(body)
	}

	reqCtx := ctx
	if reqCtx == nil {
		reqCtx = context.Background()
	}
	c.Request, _ = http.NewRequestWithContext(reqCtx, method, "/", bodyReader)
	if body != nil {
		c.Request.Header.Set("Content-Type", "application/json")
	}
	// Handlers (ValidateToken/Logout/Refresh) read the raw token from header.
	c.Request.Header.Set("Authorization", "Bearer "+token)

	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			err = &jsonrpc.Error{
				Code:    jsonrpc.CodeInternalError,
				Message: fmt.Sprintf("handler panic: %v", r),
			}
			resp = &backendResponse{Code: 500, Message: fmt.Sprintf("handler panic: %v\n%s", r, stack)}
		}
	}()

	handler(c)

	resp, err = parseBackendResponse(w)
	if err != nil {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: err.Error()}
	}
	if resp.Code == 0 || resp.Code == 409 {
		return resp, nil
	}
	return resp, backendError(resp.Code, resp.Message)
}

// hashTokenForMCP mirrors auth_handler.go's hashToken so MCP's DB token-status
// check uses the same hash key as the REST path. Must stay byte-identical to
// rest.hashToken or the lookup will miss every token.
func hashTokenForMCP(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
