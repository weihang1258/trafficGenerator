package mcp

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
	"github.com/trafficgen/trafficgen/pkg/netif"
	"go.uber.org/zap"
)

// Server is the flowB MCP server. It holds references to the engine, db, and
// iface manager (same-process direct call), plus the service account identity
// used for all tool invocations.
type Server struct {
	engine          *core.Engine
	db              *storage.DB
	ifaceMgr        *netif.Manager
	portSched       *netif.Scheduler
	jwtManager      *auth.JWTManager
	config          *config.MCPConfig
	serviceUserID   string // actual user.ID (UUID) resolved from config username
	serviceUsername string
	serviceUserRole string
	mcpServer       *mcp.Server
	filesystem      *filesystem.Filesystem
}

// SetPortScheduler injects the port scheduler. Optional: when nil, the system
// tool's interfaces action omits per-interface allocation info. main.go calls
// this after NewServer once the scheduler is initialized.
func (s *Server) SetPortScheduler(ps *netif.Scheduler) {
	s.portSched = ps
}

// SetJWTManager injects the JWT manager. Required for flowb_manage_auth's
// validate/logout/refresh actions, which parse the LLM-provided token to
// derive the caller identity (rather than using the service account).
func (s *Server) SetJWTManager(jm *auth.JWTManager) {
	s.jwtManager = jm
}

// SetFilesystem injects the content-addressed filesystem. Required for
// flowb_manage_filesystem (upload/read/delete/mkdir/rmdir/list/query). When
// nil, the filesystem tool is not registered (the server refuses to expose
// a tool it can't actually serve). main.go calls this after NewServer once
// the filesystem is constructed.
func (s *Server) SetFilesystem(fs *filesystem.Filesystem) {
	s.filesystem = fs
}

// NewServer creates a new MCP server. It validates the service account exists
// and is enabled, warns on default password, then creates the MCP server and
// registers all tools.
func NewServer(cfg *config.MCPConfig, engine *core.Engine, db *storage.DB, ifaceMgr *netif.Manager) (*Server, error) {
	s := &Server{
		engine:          engine,
		db:              db,
		ifaceMgr:        ifaceMgr,
		config:          cfg,
		serviceUsername: cfg.ServiceUserID, // config holds username; resolved to user.ID below
		serviceUserRole: cfg.ServiceUserRole,
	}

	if err := s.validateServiceAccount(); err != nil {
		return nil, err
	}

	if cfg.ServiceAccountPassword == "flowb-mcp-change-me" {
		zap.L().Warn("mcp service account using default password; change mcp.service_account_password in config")
	}

	s.mcpServer = mcp.NewServer(&mcp.Implementation{
		Name:    "flowB",
		Version: "1.0.0",
	}, nil)

	s.registerTools()

	zap.L().Info("mcp server initialized",
		zap.String("service_user", s.serviceUsername),
		zap.String("service_user_id", s.serviceUserID),
		zap.String("role", s.serviceUserRole),
	)

	return s, nil
}

// validateServiceAccount looks up the configured service account username in
// the users table and resolves it to the actual user.ID (UUID). The handler
// layer keys off user.ID for data isolation, so we must inject the UUID, not
// the username. Returns error if the user doesn't exist or is disabled --
// we refuse to start rather than auto-creating (avoiding password logging).
func (s *Server) validateServiceAccount() error {
	var user storage.UserModel
	if err := s.db.Where("username = ?", s.serviceUsername).First(&user).Error; err != nil {
		return fmt.Errorf("mcp service account %q not found in users table "+
			"(create an enabled user with this username first, or set mcp.service_user_id to an existing user): %w",
			s.serviceUsername, err)
	}
	if !user.Enabled {
		return fmt.Errorf("mcp service account %q is disabled; enable it before starting MCP server",
			s.serviceUsername)
	}
	s.serviceUserID = user.ID
	// Override role with the user's actual DB role (config role is advisory)
	if user.Role != "" {
		s.serviceUserRole = user.Role
	}
	return nil
}

// registerTools registers all flowB MCP tools. See docs/mcp-design.md §4.
func (s *Server) registerTools() {
	s.registerStrategyTools()
	s.registerLayerTools()
	s.registerTaskTools()
	s.registerWorkflowTools()
	s.registerSettingsTools()
	s.registerProfileTools()
	s.registerPortGroupTools()
	s.registerSystemTools()
	s.registerUserTools()
	s.registerAuthTools()
	s.registerPcapTools()
	s.registerFilesystemTool()
}

// Run starts the MCP server with the given transport. Blocks until the
// transport returns (e.g. stdio EOF or context cancel).
func (s *Server) Run(ctx context.Context, t mcp.Transport) error {
	return s.mcpServer.Run(ctx, t)
}

// MCP returns the underlying *mcp.Server instance. Used by the HTTP/SSE
// transport's StreamableHTTPHandler, which needs to return a *mcp.Server per
// request via its getServer callback.
func (s *Server) MCP() *mcp.Server {
	return s.mcpServer
}
