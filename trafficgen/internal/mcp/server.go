package mcp

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/google/uuid"
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
// the username.
//
// 全新数据库（v1 发布包首次启动）users 表为空：自动补建服务账号——密码
// 来自配置文件 mcp.service_account_password（不进日志，旧实现"拒绝
// auto-create 以免 password logging"的顾虑在配置驱动下不成立），幂等
// （仅 ErrRecordNotFound 时建，升级/手建场景零影响）。已存在但 disabled
// 仍拒绝启动：禁用语义优先于自动补建。
func (s *Server) validateServiceAccount() error {
	var user storage.UserModel
	if err := s.db.Where("username = ?", s.serviceUsername).First(&user).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("lookup mcp service account %q: %w", s.serviceUsername, err)
		}
		if err := s.createServiceAccount(); err != nil {
			return err
		}
		if err := s.db.Where("username = ?", s.serviceUsername).First(&user).Error; err != nil {
			return fmt.Errorf("mcp service account %q missing after auto-create: %w", s.serviceUsername, err)
		}
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

// createServiceAccount 补建 MCP 服务账号：用户名/角色取配置，密码 bcrypt
// 自配置的 ServiceAccountPassword（为空拒绝——与服务拒绝空 api_key 同理）。
func (s *Server) createServiceAccount() error {
	if s.config.ServiceAccountPassword == "" {
		return fmt.Errorf("mcp service account %q does not exist and mcp.service_account_password is empty; "+
			"set a password so the account can be created", s.serviceUsername)
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(s.config.ServiceAccountPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash mcp service account password: %w", err)
	}
	role := s.serviceUserRole
	if role == "" {
		role = "user"
	}
	account := &storage.UserModel{
		ID:           uuid.New().String(),
		Username:     s.serviceUsername,
		PasswordHash: string(passwordHash),
		Email:        s.serviceUsername + "@service.local",
		Role:         role,
		Enabled:      true,
	}
	if err := s.db.Create(account).Error; err != nil {
		return fmt.Errorf("create mcp service account %q: %w", s.serviceUsername, err)
	}
	zap.L().Info("created mcp service account",
		zap.String("username", s.serviceUsername), zap.String("role", role))
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
	s.registerTestDriveTools()
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
