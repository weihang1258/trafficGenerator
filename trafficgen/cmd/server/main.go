// Package main is the entry point for the traffic generator server.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/api/websocket"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/mcp"
	"github.com/trafficgen/trafficgen/internal/output"
	"github.com/trafficgen/trafficgen/internal/protocol/arp"
	"github.com/trafficgen/trafficgen/internal/protocol/dns"
	"github.com/trafficgen/trafficgen/internal/protocol/ftp"
	httpprotocol "github.com/trafficgen/trafficgen/internal/protocol/http"
	"github.com/trafficgen/trafficgen/internal/protocol/icmp"
	"github.com/trafficgen/trafficgen/internal/protocol/icmpv6"
	"github.com/trafficgen/trafficgen/internal/protocol/sctp"
	"github.com/trafficgen/trafficgen/internal/protocol/sip"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/replay"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
	"github.com/trafficgen/trafficgen/pkg/logger"
	"github.com/trafficgen/trafficgen/pkg/metrics"
	"github.com/trafficgen/trafficgen/pkg/netif"
	"go.uber.org/zap"
)

var (
	configPath = flag.String("config", "", "Path to configuration file")
	fsRoot     = flag.String("fs-root", "", "Filesystem root override (default: data/filesystem)")
	version    = "1.0.0"
)

// Application holds all application components.
type Application struct {
	config          *config.Config
	engine          *core.Engine
	server          *rest.Server
	wsHub           *websocket.Hub
	wsHandler       *websocket.Handler
	db              *storage.DB
	outputMgr       *output.Manager
	ifaceMgr        *netif.Manager
	portSched       *netif.Scheduler
	stopAutoRelease chan struct{}
	mcpServer       *mcp.Server
	mcpCancel       context.CancelFunc
	mcpDone         chan struct{}
	mcpHTTPCancel   context.CancelFunc
	mcpHTTPDone     chan struct{}

	// filesystem is the content-addressed filesystem used to resolve
	// FileSource payloads (relative paths) for ftp/sip/sctp/http/icmp
	// planners. Created at engine init from app.config.Filesystem.Root
	// (default "data/filesystem", overridable via --fs-root).
	filesystem *filesystem.Filesystem
	// payloadCache is the in-process dedup cache for payload bytes.
	// All 5 protocol planners that support FileSource read it via
	// core.PayloadCacheFrom(ctx) (the worker injects it into each
	// task's ctx via core.WithPayloadCache). Set on the engine once
	// at startup via SetPayloadCache.
	payloadCache *core.PayloadCache
}

func main() {
	flag.Parse()

	// Ensure pcap output directory exists
	os.MkdirAll("pcap", 0755)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// CLI override: --fs-root takes precedence over the config's
	// filesystem.root. This is the only way to override the root at
	// startup; the config default is "data/filesystem".
	applyCLIOverrides(cfg, *fsRoot)

	// Initialize logger
	if err := logger.Init(logger.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
		Output: cfg.Logging.Output,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	// If MCP stdio transport will be enabled, redirect logging to stderr NOW
	// (before any zap.L() call) -- the MCP JSON-RPC protocol owns stdout and
	// any log line there would corrupt the stream. This must run before
	// initDatabase/initEngine/initServer, all of which log on startup.
	if cfg.MCP.Enabled && cfg.MCP.Transports.Stdio && cfg.Logging.Output == "stdout" {
		fmt.Fprintln(os.Stderr, "mcp stdio enabled; forcing log output to stderr to avoid corrupting JSON-RPC stream")
		if err := logger.Init(logger.Config{
			Level:  cfg.Logging.Level,
			Format: cfg.Logging.Format,
			Output: "stderr",
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to redirect logger: %v\n", err)
			os.Exit(1)
		}
	}

	defer logger.Sync()

	zap.L().Info("starting traffic generator",
		zap.String("version", version),
	)

	// Create application
	app := &Application{
		config: cfg,
	}

	// Initialize database
	if err := app.initDatabase(); err != nil {
		zap.L().Fatal("failed to init database", zap.Error(err))
	}

	// Initialize interface manager
	if err := app.initInterfaceManager(); err != nil {
		zap.L().Warn("interface manager init failed", zap.Error(err))
	}

	// Initialize port scheduler
	app.initPortScheduler()

	// Initialize output manager
	app.initOutputManager()

	// Initialize engine
	if err := app.initEngine(); err != nil {
		zap.L().Fatal("failed to init engine", zap.Error(err))
	}

	// Initialize WebSocket
	app.initWebSocket()

	// Initialize API server
	if err := app.initServer(); err != nil {
		zap.L().Fatal("failed to init server", zap.Error(err))
	}

	// Initialize MCP server (optional, only if enabled). Must come after
	// initServer so the REST server's TaskHandler already owns the engine
	// callbacks (OnTaskComplete etc.) -- MCP's TaskHandler is created with
	// registerCallbacks=false to avoid clobbering them.
	app.initMCPServer()

	// Start all components
	if err := app.Start(); err != nil {
		zap.L().Fatal("failed to start", zap.Error(err))
	}

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	zap.L().Info("shutting down...")

	// Graceful shutdown
	app.Stop()

	zap.L().Info("server stopped")
}

// initDatabase initializes the database connection.
func (app *Application) initDatabase() error {
	db, err := storage.NewDBWithAdmin(&app.config.Database, &app.config.Auth.Admin)
	if err != nil {
		return fmt.Errorf("database init: %w", err)
	}
	app.db = db

	zap.L().Info("database connected",
		zap.String("type", app.config.Database.Type),
		zap.String("admin_user", app.config.Auth.Admin.Username),
	)

	return nil
}

// initInterfaceManager initializes the interface manager.
func (app *Application) initInterfaceManager() error {
	app.ifaceMgr = netif.NewManager()

	if err := app.ifaceMgr.Discover(); err != nil {
		return err
	}

	zap.L().Info("interface manager initialized",
		zap.Int("interfaces", len(app.ifaceMgr.List())),
	)

	return nil
}

// initPortScheduler initializes the port scheduler.
func (app *Application) initPortScheduler() {
	app.portSched = netif.NewScheduler()
	app.stopAutoRelease = app.portSched.StartAutoRelease(30 * time.Second)

	zap.L().Info("port scheduler initialized")
}

// initOutputManager initializes the output manager.
func (app *Application) initOutputManager() {
	app.outputMgr = output.NewManager()

	zap.L().Info("output manager initialized")
}

// initEngine initializes the traffic engine.
func (app *Application) initEngine() error {
	// Load persisted settings; buffer_size only takes effect at startup
	// (the ring buffer is fixed-size). log_level and max_tasks are applied below.
	bufferSize := app.config.Engine.BufferSize
	if app.db != nil {
		if s, err := app.db.GetSettings(); err == nil {
			if s.BufferSize > 0 {
				bufferSize = s.BufferSize
			}
		} else {
			zap.L().Warn("failed to load settings for engine init, using config defaults", zap.Error(err))
		}
	}

	app.engine = core.NewEngine(core.EngineConfig{
		ConfigWorkers:  app.config.Engine.ConfigWorkers,
		PacketWorkers:  app.config.Engine.PacketWorkers,
		OutputWorkers:  app.config.Engine.OutputWorkers,
		BufferSize:     bufferSize,
		QueueSize:      app.config.Engine.QueueSize,
		MaxBufferBytes: 100 * 1024 * 1024, // 100MB
		MinMTU:         app.config.Engine.MinMTU,
	})

	// Construct the content-addressed filesystem and PayloadCache. The
	// cache is read by ftp/sip/sctp/http/icmp planners via
	// core.PayloadCacheFrom(ctx); the worker injects it via
	// core.WithPayloadCache. The root path comes from
	// app.config.Filesystem.Root (default "data/filesystem", overridable
	// via the --fs-root CLI flag). filesystem.New creates the root +
	// required subdirs (.meta/files, blobs) if missing, so a fresh
	// deploy just works.
	fsRoot := app.config.Filesystem.Root
	fs, err := filesystem.New(fsRoot)
	if err != nil {
		// A failure here doesn't abort engine startup: the engine
		// still works for all non-FileSource flows. Planners treat a
		// nil cache as "skip FileSource resolution" rather than
		// panicking, so we log the error and continue without a
		// cache. Task 14 may promote this to a fatal error.
		zap.L().Warn("filesystem init failed; FileSource payloads will not resolve",
			zap.String("root", fsRoot),
			zap.Error(err),
		)
	} else {
		app.filesystem = fs
		app.payloadCache = core.NewPayloadCache(fs)
		app.engine.SetPayloadCache(app.payloadCache)
		zap.L().Info("payload cache wired",
			zap.String("fs_root", fsRoot),
		)
	}

	// Apply persisted runtime settings now that the engine exists.
	if app.db != nil {
		if s, err := app.db.GetSettings(); err == nil {
			app.engine.SetMaxTasks(s.MaxTasks)
			if s.LogLevel != "" {
				if err := logger.SetLevel(s.LogLevel); err == nil {
					zap.L().Info("applied persisted log level", zap.String("level", s.LogLevel))
				}
			}
		}
	}

	// Register protocol planners directly to engine
	app.engine.RegisterPlanner(tcp.NewPlanner())
	app.engine.RegisterPlanner(udp.NewPlanner())
	app.engine.RegisterPlanner(httpprotocol.NewPlanner())
	app.engine.RegisterPlanner(dns.NewPlanner())
	app.engine.RegisterPlanner(icmp.NewPlanner())
	app.engine.RegisterPlanner(arp.NewPlanner())
	app.engine.RegisterPlanner(ftp.NewPlanner())
	app.engine.RegisterPlanner(sip.NewPlanner())
	app.engine.RegisterPlanner(sctp.NewPlanner())
	app.engine.RegisterPlanner(icmpv6.NewPlanner())

	zap.L().Info("protocols registered",
		zap.Strings("protocols", app.engine.ListProtocols()),
	)

	// Set packet builder. The buildFunc dispatches between synth (builder.Build)
	// and replay (rewriter.ApplyPatches) based on the _replay metadata flag.
	builder := core.NewBuilder()
	app.engine.SetBuildFunc(replay.NewBuildFunc(builder.Build))

	// Register the replay planner (handles TrafficClass.Type=="replay").
	app.engine.SetReplayPlanner(replay.NewReplayPlanner(app.db))

	return nil
}

// initWebSocket initializes WebSocket handler.
func (app *Application) initWebSocket() {
	app.wsHub = websocket.NewHub()
	app.wsHandler = websocket.NewHandler(app.wsHub)

	go app.wsHub.Run()

	zap.L().Info("websocket hub started")
}

// initServer initializes the API server.
func (app *Application) initServer() error {
	app.server = rest.NewServer(app.config, app.engine, app.wsHandler, app.db, app.ifaceMgr, app.portSched)
	return app.server.Setup()
}

// initMCPServer initializes the MCP server if enabled. The MCP server shares
// the same engine/db/ifaceMgr as the REST server and invokes handler methods
// directly via constructed gin.Context (no HTTP hop). Logger redirection for
// stdio transport is handled in main() before any zap.L() call.
func (app *Application) initMCPServer() {
	if !app.config.MCP.Enabled {
		return
	}

	srv, err := mcp.NewServer(&app.config.MCP, app.engine, app.db, app.ifaceMgr)
	if err != nil {
		zap.L().Fatal("failed to init mcp server", zap.Error(err))
	}
	srv.SetPortScheduler(app.portSched)
	// JWT manager is needed by flowb_manage_auth (validate/logout/refresh
	// parse the LLM-provided token to derive caller identity).
	jwtManager := auth.NewJWTManager(
		app.config.Auth.JWTSecret,
		app.config.Auth.JWTIssuer,
		time.Duration(app.config.Auth.JWTExpiresIn)*time.Hour,
	)
	srv.SetJWTManager(jwtManager)
	app.mcpServer = srv
}

// startMCPServer runs the MCP server on stdio in a goroutine. Blocks until
// stdin EOF or context cancel. No-op if MCP is disabled.
func (app *Application) startMCPServer() {
	if app.mcpServer == nil {
		return
	}
	if !app.config.MCP.Transports.Stdio {
		zap.L().Warn("mcp enabled but stdio transport disabled; skipping stdio")
	} else {
		ctx, cancel := context.WithCancel(context.Background())
		app.mcpCancel = cancel
		app.mcpDone = make(chan struct{})

		go func() {
			defer close(app.mcpDone)
			zap.L().Info("starting mcp server (stdio)")
			if err := app.mcpServer.Run(ctx, mcp.NewStdioTransport()); err != nil {
				zap.L().Error("mcp server ended with error", zap.Error(err))
			}
			zap.L().Info("mcp server stopped")
		}()
	}

	// Start HTTP transport if enabled (Phase 3 -- remote MCP primary use case).
	if app.config.MCP.Transports.HTTP.Enabled {
		httpCtx, httpCancel := context.WithCancel(context.Background())
		app.mcpHTTPCancel = httpCancel
		app.mcpHTTPDone = make(chan struct{})

		go func() {
			defer close(app.mcpHTTPDone)
			if err := app.startMCPHTTP(httpCtx); err != nil {
				zap.L().Error("mcp http server ended with error", zap.Error(err))
			}
			zap.L().Info("mcp http server stopped")
		}()
	}
}

// startMCPHTTP constructs and runs the MCP HTTP transport. Blocks until ctx
// is canceled or the server returns a fatal error.
func (app *Application) startMCPHTTP(ctx context.Context) error {
	httpSrv, err := mcp.NewHTTPServer(
		app.mcpServer,
		app.config.MCP.Transports.HTTP.Listen,
		app.config.MCP.APIKey,
		app.config.MCP.Transports.HTTP.CORSOrigins,
	)
	if err != nil {
		return fmt.Errorf("init mcp http server: %w", err)
	}

	zap.L().Info("starting mcp http server",
		zap.String("listen", app.config.MCP.Transports.HTTP.Listen),
	)
	return httpSrv.Start(ctx)
}

// Start starts all components.
func (app *Application) Start() error {
	// Start engine
	if err := app.engine.Start(); err != nil {
		return fmt.Errorf("engine start: %w", err)
	}

	// Start HTTP server
	go func() {
		zap.L().Info("starting HTTP server",
			zap.String("host", app.config.Server.Host),
			zap.Int("port", app.config.Server.Port),
		)
		if err := app.server.Start(); err != nil && err != http.ErrServerClosed {
			zap.L().Fatal("server error", zap.Error(err))
		}
	}()

	// Start metrics update
	go app.updateMetrics()

	// Start MCP server (no-op if disabled)
	app.startMCPServer()

	return nil
}

// Stop stops all components.
func (app *Application) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop MCP servers first: cancel their Run contexts (stdio transport
	// returns on ctx.Done; HTTP server initiates graceful Shutdown), then
	// wait for goroutines to exit before tearing down engine/db -- an
	// in-flight tool call may be using both. Bound the wait by the shutdown
	// deadline so a wedged MCP goroutine cannot block exit.
	if app.mcpCancel != nil {
		app.mcpCancel()
	}
	if app.mcpDone != nil {
		select {
		case <-app.mcpDone:
		case <-ctx.Done():
			zap.L().Warn("mcp stdio server did not stop within shutdown deadline")
		}
	}

	if app.mcpHTTPCancel != nil {
		app.mcpHTTPCancel()
	}
	if app.mcpHTTPDone != nil {
		select {
		case <-app.mcpHTTPDone:
		case <-ctx.Done():
			zap.L().Warn("mcp http server did not stop within shutdown deadline")
		}
	}

	// Stop HTTP server
	if err := app.server.Shutdown(ctx); err != nil {
		zap.L().Error("server shutdown error", zap.Error(err))
	}

	// Stop engine
	app.engine.Stop()

	// Stop port scheduler auto-release
	if app.stopAutoRelease != nil {
		close(app.stopAutoRelease)
	}

	// Close output manager
	if app.outputMgr != nil {
		app.outputMgr.Close()
	}

	// Close database
	if app.db != nil {
		app.db.Close()
	}
}

// updateMetrics periodically updates Prometheus metrics.
func (app *Application) updateMetrics() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Update buffer metrics
		status := app.engine.GetBufferStatus()
		if status != nil {
			if combined, ok := status["combined"].(map[string]interface{}); ok {
				if count, ok := combined["count"].(int); ok {
					if size, ok := combined["size"].(int); ok && size > 0 {
						metrics.SetBufferUsage("combined", float64(count)/float64(size)*100)
						metrics.SetBufferSize("combined", float64(size))
					}
				}
			}
		}

		// Update port allocation metrics
		if app.portSched != nil {
			stats := app.portSched.Stats()
			if allocations, ok := stats["allocations"].(int); ok {
				metrics.SetPortAllocations(float64(allocations))
			}
			if waitQueue, ok := stats["wait_queue"].(int); ok {
				metrics.SetPortWaitQueue(float64(waitQueue))
			}
		}

		// Update WebSocket connections
		if app.wsHub != nil {
			metrics.SetWebSocketConnections(float64(app.wsHub.ClientCount()))
		}
	}
}
