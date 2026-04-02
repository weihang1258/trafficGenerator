package rest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/trafficgen/trafficgen/internal/api/websocket"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
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
}

// NewServer creates a new REST API server.
func NewServer(cfg *config.Config, engine *core.Engine, wsHandler *websocket.Handler, db *storage.DB, ifaceMgr *netif.Manager) *Server {
	return &Server{
		config:    cfg,
		engine:    engine,
		wsHandler: wsHandler,
		db:        db,
		ifaceMgr:  ifaceMgr,
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
	// Handlers
	taskHandler := NewTaskHandler(s.engine)
	systemHandler := NewSystemHandler(s.engine)

	// Health endpoints (no auth required)
	s.router.GET("/health", systemHandler.HealthCheck)
	s.router.GET("/ready", systemHandler.ReadyCheck)

	// WebSocket endpoint
	if s.wsHandler != nil {
		s.router.GET("/ws", s.wsHandler.Handle)
	}

	// Prometheus metrics
	if s.config.Metrics.Enabled {
		s.router.GET(s.config.Metrics.Path, gin.WrapH(promhttp.Handler()))
	}

	// API v1 routes
	v1 := s.router.Group("/api/v1")
	{
		// Task routes
		tasks := v1.Group("/tasks")
		{
			tasks.POST("", taskHandler.Create)
			tasks.GET("", taskHandler.List)
			tasks.GET("/:id", taskHandler.Get)
			tasks.POST("/:id/start", taskHandler.Start)
			tasks.POST("/:id/stop", taskHandler.Stop)
			tasks.DELETE("/:id", taskHandler.Delete)
			tasks.GET("/:id/packets", taskHandler.GetPackets)
		}

		// System routes
		system := v1.Group("/system")
		{
			system.GET("/status", systemHandler.GetStatus)
			system.GET("/protocols", systemHandler.GetProtocols)
			system.GET("/stats", systemHandler.GetStats)
		}

		// Interface routes
		interfaces := v1.Group("/interfaces")
		{
			interfaces.GET("", s.listInterfaces)
			interfaces.POST("/discover", s.discoverInterfaces)
		}

		// Strategy routes
		strategies := v1.Group("/strategies")
		{
			strategies.POST("", s.createStrategy)
			strategies.GET("", s.listStrategies)
			strategies.GET("/:id", s.getStrategy)
			strategies.PUT("/:id", s.updateStrategy)
			strategies.DELETE("/:id", s.deleteStrategy)
		}

		// Settings routes
		settings := v1.Group("/settings")
		{
			settings.GET("", s.getSettings)
			settings.PUT("", s.updateSettings)
		}

		// Auth routes (no auth required)
		auth := v1.Group("/auth")
		{
			auth.POST("/login", s.login)
			auth.POST("/logout", s.logout)
			auth.POST("/refresh", s.refreshToken)
		}
	}
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

// CORSMiddleware handles CORS.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
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

func (s *Server) createStrategy(c *gin.Context) {
	var req CreateStrategyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Generate ID
	b := make([]byte, 8)
	rand.Read(b)
	id := "strategy-" + hex.EncodeToString(b)

	// Serialize config
	configJSON, _ := json.Marshal(req.Config)

	strategy := &storage.StrategyModel{
		ID:       id,
		Name:     req.Name,
		Protocol: req.Protocol,
		Config:   string(configJSON),
	}

	if err := s.db.Create(strategy).Error; err != nil {
		InternalError(c, "failed to create strategy: "+err.Error())
		return
	}

	Created(c, map[string]string{"id": id})
}

func (s *Server) listStrategies(c *gin.Context) {
	var strategies []storage.StrategyModel
	if err := s.db.Find(&strategies).Error; err != nil {
		InternalError(c, "failed to list strategies: "+err.Error())
		return
	}

	result := make([]StrategyResponse, len(strategies))
	for i, s := range strategies {
		var config map[string]interface{}
		json.Unmarshal([]byte(s.Config), &config)
		result[i] = StrategyResponse{
			ID:        s.ID,
			Name:      s.Name,
			Protocol:  s.Protocol,
			Config:    config,
			CreatedAt: s.CreatedAt.Unix(),
			UpdatedAt: s.UpdatedAt.Unix(),
		}
	}

	Success(c, result)
}

func (s *Server) getStrategy(c *gin.Context) {
	id := c.Param("id")

	var strategy storage.StrategyModel
	if err := s.db.First(&strategy, "id = ?", id).Error; err != nil {
		NotFound(c, "strategy not found")
		return
	}

	var config map[string]interface{}
	json.Unmarshal([]byte(strategy.Config), &config)

	Success(c, StrategyResponse{
		ID:        strategy.ID,
		Name:      strategy.Name,
		Protocol:  strategy.Protocol,
		Config:    config,
		CreatedAt: strategy.CreatedAt.Unix(),
		UpdatedAt: strategy.UpdatedAt.Unix(),
	})
}

func (s *Server) updateStrategy(c *gin.Context) {
	id := c.Param("id")

	var strategy storage.StrategyModel
	if err := s.db.First(&strategy, "id = ?", id).Error; err != nil {
		NotFound(c, "strategy not found")
		return
	}

	var req CreateStrategyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	configJSON, _ := json.Marshal(req.Config)
	strategy.Name = req.Name
	strategy.Protocol = req.Protocol
	strategy.Config = string(configJSON)

	if err := s.db.Save(&strategy).Error; err != nil {
		InternalError(c, "failed to update strategy: "+err.Error())
		return
	}

	SuccessWithMessage(c, "strategy updated", nil)
}

func (s *Server) deleteStrategy(c *gin.Context) {
	id := c.Param("id")

	if err := s.db.Delete(&storage.StrategyModel{}, "id = ?", id).Error; err != nil {
		InternalError(c, "failed to delete strategy: "+err.Error())
		return
	}

	SuccessWithMessage(c, "strategy deleted", nil)
}

func (s *Server) getSettings(c *gin.Context) {
	Success(c, SettingsResponse{
		MaxTasks:   100,
		BufferSize: 4096,
		LogLevel:   "info",
	})
}

func (s *Server) updateSettings(c *gin.Context) {
	var req UpdateSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}
	SuccessWithMessage(c, "settings updated", nil)
}

func (s *Server) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// TODO: Implement actual authentication
	if req.Username == "admin" && req.Password == "admin" {
		Success(c, LoginResponse{
			Token:     "dummy-token",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		})
		return
	}

	Unauthorized(c, "invalid credentials")
}

func (s *Server) logout(c *gin.Context) {
	SuccessWithMessage(c, "logged out", nil)
}

func (s *Server) refreshToken(c *gin.Context) {
	Success(c, LoginResponse{
		Token:     "new-dummy-token",
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	})
}
