package rest

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/trafficgen/trafficgen/internal/api/websocket"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/netif"
)

// Server represents the REST API server.
type Server struct {
	config     *config.Config
	engine     *core.Engine
	db         *storage.DB
	ifaceMgr   *netif.Manager
	httpServer *http.Server
	router     *gin.Engine
	wsHandler  *websocket.Handler
	jwtManager *auth.JWTManager
}

// NewServer creates a new REST API server.
func NewServer(cfg *config.Config, engine *core.Engine, wsHandler *websocket.Handler, db *storage.DB, ifaceMgr *netif.Manager) *Server {
	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(
		cfg.Auth.JWTSecret,
		cfg.Auth.JWTIssuer,
		time.Duration(cfg.Auth.JWTExpiresIn)*time.Hour,
	)

	return &Server{
		config:     cfg,
		engine:     engine,
		wsHandler:  wsHandler,
		db:         db,
		ifaceMgr:   ifaceMgr,
		jwtManager: jwtManager,
	}
}

// Setup initializes the server.
func (s *Server) Setup() error {
	// Set Gin mode
	switch s.config.Server.Mode {
	case "release":
		gin.SetMode(gin.ReleaseMode)
	case "test":
		gin.SetMode(gin.TestMode)
	default:
		gin.SetMode(gin.DebugMode)
	}

	// Create router
	s.router = gin.New()

	// Add middleware
	s.router.Use(gin.Recovery())
	s.router.Use(CORSMiddleware())
	s.router.Use(LoggerMiddleware())

	// Setup routes
	s.setupRoutes()

	return nil
}

// setupRoutes configures all API routes.
func (s *Server) setupRoutes() {
	// Create handlers
	authHandler := NewAuthHandler(s.db, s.jwtManager)
	strategyHandler := NewStrategyHandler(s.db)
	taskHandler := NewTaskHandler(s.db, s.engine)
	portGroupHandler := NewPortGroupHandler(s.db)
	systemHandler := NewSystemHandler(s.engine)
	settingsHandler := NewSettingsHandler()
	userHandler := NewUserHandler(s.db)

	// Health endpoints (no auth required)
	s.router.GET("/health", systemHandler.HealthCheck)
	s.router.GET("/ready", systemHandler.ReadyCheck)

	// WebSocket endpoint (no auth required for now)
	if s.wsHandler != nil {
		s.router.GET("/ws", s.wsHandler.Handle)
	}

	// Prometheus metrics (no auth required)
	if s.config.Metrics.Enabled {
		s.router.GET(s.config.Metrics.Path, gin.WrapH(promhttp.Handler()))
	}

	// Auth routes (no auth required)
	authGroup := s.router.Group("/api/v1/auth")
	{
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/login", authHandler.Login)
		authGroup.GET("/validate", authHandler.ValidateToken)
		authGroup.POST("/logout", authHandler.Logout)
	}

	// Port routes (no auth required - public data)
	portsGroup := s.router.Group("/api/v1/ports")
	{
		portsGroup.GET("", s.listPorts)
	}

	// Port group routes (public data, but creation requires auth)
	portGroupsGroup := s.router.Group("/api/v1/port-groups")
	{
		portGroupsGroup.GET("", portGroupHandler.List)
		portGroupsGroup.GET("/:id", portGroupHandler.Get)
	}

	// Authenticated routes
	authMiddleware := auth.AuthMiddleware(s.jwtManager)

	api := s.router.Group("/api/v1")
	api.Use(authMiddleware)
	{
		// User profile routes (authenticated user can manage own account)
		api.GET("/user/profile", authHandler.GetProfile)
		api.PUT("/user/profile", authHandler.UpdateProfile)
		api.DELETE("/user/profile", authHandler.DeleteProfile)

		// Strategy routes
		strategies := api.Group("/strategies")
		{
			strategies.POST("", strategyHandler.Create)
			strategies.GET("", strategyHandler.List)
			strategies.GET("/:id", strategyHandler.Get)
			strategies.PUT("/:id", strategyHandler.Update)
			strategies.DELETE("/:id", strategyHandler.Delete)
		}

		// Task routes
		tasks := api.Group("/tasks")
		{
			tasks.POST("", taskHandler.Create)
			tasks.GET("", taskHandler.List)
			tasks.GET("/:id", taskHandler.Get)
			tasks.POST("/:id/start", taskHandler.Start)
			tasks.POST("/:id/stop", taskHandler.Stop)
			tasks.DELETE("/:id", taskHandler.Delete)
		}

		// Port group creation (requires auth)
		api.POST("/port-groups", portGroupHandler.Create)
		api.DELETE("/port-groups/:id", portGroupHandler.Delete)

		// System routes
		system := api.Group("/system")
		{
			system.GET("/status", systemHandler.GetStatus)
			system.GET("/protocols", systemHandler.GetProtocols)
			system.GET("/stats", systemHandler.GetStats)
		}

		// Interface routes
		interfaces := api.Group("/interfaces")
		{
			interfaces.GET("", s.listInterfaces)
			interfaces.POST("/discover", s.discoverInterfaces)
		}

		// Settings routes
		api.GET("/settings", settingsHandler.Get)
		api.PUT("/settings", settingsHandler.Update)

		// Auth refresh route
		api.POST("/auth/refresh", authHandler.Refresh)

		// User management routes (admin only)
		api.GET("/users", userHandler.List)
		api.GET("/users/:id", userHandler.Get)
		api.PUT("/users/:id", userHandler.Update)
		api.DELETE("/users/:id", userHandler.Delete)
		api.POST("/users/:id/reset-password", userHandler.ResetPassword)

		// History route
		api.GET("/history", taskHandler.History)
	}

	// Serve frontend static files
	s.router.Static("/assets", "./web/dist/assets")
	s.router.StaticFile("/favicon.ico", "./web/dist/favicon.ico")

	// Handle all other routes by serving index.html (for SPA routing)
	s.router.NoRoute(func(c *gin.Context) {
		c.File("./web/dist/index.html")
	})
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Router returns the Gin router for testing.
func (s *Server) Router() *gin.Engine {
	return s.router
}

// CORSMiddleware handles CORS.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			origin = "*"
		}
		c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// LoggerMiddleware logs requests.
func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		// Log using Zap if available
		// logger.Info("request",
		// 	zap.String("method", method),
		// 	zap.String("path", path),
		// 	zap.Int("status", status),
		// 	zap.Duration("latency", latency),
		// )

		_ = latency
		_ = status
		_ = method
		_ = path
	}
}

// Interface handlers

func (s *Server) listInterfaces(c *gin.Context) {
	if s.ifaceMgr == nil {
		Success(c, []InterfaceResponse{})
		return
	}

	interfaces := s.ifaceMgr.List()
	result := make([]InterfaceResponse, len(interfaces))
	for i, iface := range interfaces {
		ip := ""
		if len(iface.IPs) > 0 {
			ip = iface.IPs[0].String()
		}
		result[i] = InterfaceResponse{
			Name:        iface.Name,
			MAC:         iface.MAC.String(),
			IP:          ip,
			IsUp:        iface.IsUp,
			LinkUp:      iface.LinkUp,
			MTU:         iface.MTU,
			Description: iface.Description,
		}
	}

	Success(c, result)
}

func (s *Server) discoverInterfaces(c *gin.Context) {
	if s.ifaceMgr == nil {
		InternalError(c, "interface manager not initialized")
		return
	}

	if err := s.ifaceMgr.Refresh(); err != nil {
		InternalError(c, "failed to discover interfaces: "+err.Error())
		return
	}

	SuccessWithMessage(c, "discovery completed", map[string]int{
		"count": len(s.ifaceMgr.List()),
	})
}

// listPorts lists all ports with status
func (s *Server) listPorts(c *gin.Context) {
	var ports []storage.PortModel
	if err := s.db.Find(&ports).Error; err != nil {
		InternalError(c, "failed to list ports: "+err.Error())
		return
	}

	result := make([]map[string]interface{}, len(ports))
	for i, port := range ports {
		result[i] = map[string]interface{}{
			"id":              port.ID,
			"name":            port.Name,
			"type":            port.Type,
			"pci_address":     port.PCIAddress,
			"status":          port.Status,
			"current_task_id": port.CurrentTaskID,
			"created_at":      port.CreatedAt.Unix(),
			"updated_at":      port.UpdatedAt.Unix(),
		}
	}

	Success(c, result)
}

