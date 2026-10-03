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
	"github.com/trafficgen/trafficgen/pkg/filesystem"
	"github.com/trafficgen/trafficgen/pkg/netif"
)

// Server represents the REST API server.
type Server struct {
	config     *config.Config
	engine     *core.Engine
	db         *storage.DB
	ifaceMgr   *netif.Manager
	portSched  *netif.Scheduler
	httpServer *http.Server
	router     *gin.Engine
	wsHandler  *websocket.Handler
	jwtManager *auth.JWTManager

	// filesystem is the content-addressed filesystem exposed via
	// /api/v1/fs/* routes (Upload/Download/Info/DeleteFile/Mkdir/Rmdir/
	// List). When nil, no fs routes are registered (graceful
	// degradation if the filesystem init failed at startup).
	filesystem *filesystem.Filesystem
}

// SetFilesystem wires a content-addressed filesystem into the server.
// Must be called before Setup() so routes are registered.
func (s *Server) SetFilesystem(fs *filesystem.Filesystem) {
	s.filesystem = fs
}

// NewServer creates a new REST API server.
func NewServer(cfg *config.Config, engine *core.Engine, wsHandler *websocket.Handler, db *storage.DB, ifaceMgr *netif.Manager, portSched *netif.Scheduler) *Server {
	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(
		cfg.Auth.JWTSecret,
		cfg.Auth.JWTIssuer,
		time.Duration(cfg.Auth.JWTExpiresIn)*time.Hour,
	)

	// Inject JWT manager into WebSocket handler for authentication
	if wsHandler != nil {
		wsHandler.SetJWTManager(jwtManager)
	}

	return &Server{
		config:     cfg,
		engine:     engine,
		wsHandler:  wsHandler,
		db:         db,
		ifaceMgr:   ifaceMgr,
		portSched:  portSched,
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
	s.router.Use(CORSMiddleware(s.config.Server.AllowedOrigins))
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
	taskHandler := NewTaskHandler(s.db, s.engine, s.wsHandler)
	portGroupHandler := NewPortGroupHandler(s.db)
	systemHandler := NewSystemHandler(s.engine)
	systemHandler.SetDB(s.db)
	settingsHandler := NewSettingsHandler(s.db, s.engine)
	userHandler := NewUserHandler(s.db)
	pcapHandler := NewPcapHandler(s.db, "")
	// Task pcap auto-registration: completed pcap products are imported into
	// the asset library (size-capped) by the REST server's completion callback.
	taskHandler.SetPcapHandler(pcapHandler)

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

	// Public download links (no auth — task UUID is the capability token):
	// generated pcap files, for external clients' curl convenience.
	s.router.GET("/downloads/tasks/:id/pcap", pcapHandler.DownloadByTask)
	// Public pcap asset downloads (no auth — asset UUID is the capability
	// token): imported assets and auto-registered task products.
	s.router.GET("/downloads/pcaps/:id/download", func(c *gin.Context) {
		ServePcapPublic(s.db, c.Writer, c.Request)
	})

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

	// Filesystem routes (public; filesystem layer enforces root-scoped
	// path validation, rejecting absolute paths and traversal escape).
	// Registered only when a filesystem is configured.
	if s.filesystem != nil {
		fsHandler := NewFilesystemHandler(s.filesystem)
		fsGroup := s.router.Group("/api/v1/fs")
		{
			fsGroup.POST("/files/*path", fsHandler.Upload)
			fsGroup.GET("/files/*path", func(c *gin.Context) {
				switch c.Query("op") {
				case "info":
					fsHandler.Info(c)
				case "download", "":
					fsHandler.Download(c)
				default:
					BadRequest(c, "unknown op: "+c.Query("op"))
				}
			})
			fsGroup.DELETE("/files/*path", fsHandler.DeleteFile)
			fsGroup.POST("/dirs/*path", fsHandler.Mkdir)
			fsGroup.DELETE("/dirs/*path", fsHandler.Rmdir)
			fsGroup.GET("/list", fsHandler.List)
		}
	}

	// Authenticated routes
	authMiddleware := auth.AuthMiddlewareWithDB(s.jwtManager, s.db.DB)

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
				strategies.GET("/:id/tasks", strategyHandler.ListTasks)
			strategies.PUT("/:id", strategyHandler.Update)
			strategies.DELETE("/:id", strategyHandler.Delete)
		}

		// Task routes
		tasks := api.Group("/tasks")
		{
			tasks.POST("", taskHandler.Create)
			tasks.POST("/batch", taskHandler.CreateBatch)
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

		// PCAP asset routes (§15/§19)
		pcaps := api.Group("/pcaps")
		{
			pcaps.POST("", pcapHandler.Import)
			pcaps.GET("", pcapHandler.List)
			pcaps.GET("/:id", pcapHandler.Get)
			pcaps.DELETE("/:id", pcapHandler.Delete)
			pcaps.GET("/:id/flows", pcapHandler.ListFlows)
			pcaps.GET("/:id/flows/:fid", pcapHandler.GetFlow)
			pcaps.GET("/:id/flows/:fid/packets", pcapHandler.ListPackets)
			pcaps.GET("/:id/flows/:fid/stream", pcapHandler.GetStream)
			pcaps.GET("/:id/flows/:fid/body", pcapHandler.GetBody)
			pcaps.GET("/:id/packets", pcapHandler.ListPacketsByAsset)
			pcaps.GET("/:id/packets/:pid", pcapHandler.GetPacket)
			pcaps.GET("/:id/packets/:pid/payload", pcapHandler.GetPacketPayload)
			pcaps.POST("/:id/search", pcapHandler.Search)
			pcaps.POST("/:id/match-preview", pcapHandler.MatchPreview)
			pcaps.POST("/:id/extract", pcapHandler.Extract)
			pcaps.GET("/:id/download", pcapHandler.Download)
			pcaps.POST("/:id/reparse", pcapHandler.Reparse)
		}
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

// CORSMiddleware handles CORS with origin whitelist validation.
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Validate origin against allowed list
		allowed := false
		if origin != "" {
			for _, o := range allowedOrigins {
				if o == origin || o == "*" {
					allowed = true
					break
				}
			}
		}

		if !allowed && origin != "" {
			// Origin not in whitelist - deny CORS but let the request proceed
			// (browser will block the response anyway)
			c.Next()
			return
		}

		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}
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

	// Build a set of interfaces that have active port allocations
	inUseMap := make(map[string][]PortAllocationBrief)
	if s.portSched != nil {
		for _, alloc := range s.portSched.ListAllocations() {
			brief := PortAllocationBrief{
				Port:        alloc.Port,
				TaskID:      alloc.TaskID,
				AllocatedAt: alloc.AllocatedAt.Format(time.RFC3339),
			}
			inUseMap[alloc.Interface] = append(inUseMap[alloc.Interface], brief)
		}
	}

	interfaces := s.ifaceMgr.List()
	result := make([]InterfaceResponse, len(interfaces))
	for i, iface := range interfaces {
		// Collect all IP addresses
		ips := make([]string, len(iface.IPs))
		for j, ip := range iface.IPs {
			ips[j] = ip.String()
		}

		allocs := inUseMap[iface.Name]

		result[i] = InterfaceResponse{
			Name:        iface.Name,
			MAC:         iface.MAC.String(),
			IPs:         ips,
			IsUp:        iface.IsUp,
			LinkUp:      iface.LinkUp,
			MTU:         iface.MTU,
			Description: iface.Description,
			IsVirtual:   iface.IsVirtual,
			InUse:       len(allocs) > 0,
			Allocations: allocs,
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

