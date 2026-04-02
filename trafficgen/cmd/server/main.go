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
	"github.com/trafficgen/trafficgen/internal/output"
	"github.com/trafficgen/trafficgen/internal/protocol/arp"
	"github.com/trafficgen/trafficgen/internal/protocol/dns"
	httpprotocol "github.com/trafficgen/trafficgen/internal/protocol/http"
	"github.com/trafficgen/trafficgen/internal/protocol/icmp"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/logger"
	"github.com/trafficgen/trafficgen/pkg/metrics"
	"github.com/trafficgen/trafficgen/pkg/netif"
	"go.uber.org/zap"
)

var (
	configPath = flag.String("config", "", "Path to configuration file")
	version    = "1.0.0"
)

// Application holds all application components.
type Application struct {
	config       *config.Config
	engine       *core.Engine
	server       *rest.Server
	wsHub        *websocket.Hub
	wsHandler    *websocket.Handler
	db           *storage.DB
	outputMgr    *output.Manager
	ifaceMgr     *netif.Manager
	portSched    *netif.Scheduler
	stopAutoRelease chan struct{}
}

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.Init(logger.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
		Output: cfg.Logging.Output,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
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
	db, err := storage.NewDB(&app.config.Database)
	if err != nil {
		return fmt.Errorf("database init: %w", err)
	}
	app.db = db

	zap.L().Info("database connected",
		zap.String("type", app.config.Database.Type),
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
	app.engine = core.NewEngine(core.EngineConfig{
		ConfigWorkers:  app.config.Engine.ConfigWorkers,
		PacketWorkers:  app.config.Engine.PacketWorkers,
		OutputWorkers:  app.config.Engine.OutputWorkers,
		BufferSize:     app.config.Engine.BufferSize,
		QueueSize:      app.config.Engine.QueueSize,
		MaxBufferBytes: 100 * 1024 * 1024, // 100MB
	})

	// Register protocol planners directly to engine
	app.engine.RegisterPlanner(tcp.NewPlanner())
	app.engine.RegisterPlanner(udp.NewPlanner())
	app.engine.RegisterPlanner(httpprotocol.NewPlanner())
	app.engine.RegisterPlanner(dns.NewPlanner())
	app.engine.RegisterPlanner(icmp.NewPlanner())
	app.engine.RegisterPlanner(arp.NewPlanner())

	zap.L().Info("protocols registered",
		zap.Strings("protocols", app.engine.ListProtocols()),
	)

	// Set packet builder
	builder := core.NewBuilder()
	app.engine.SetBuildFunc(builder.Build)

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
	app.server = rest.NewServer(app.config, app.engine)
	return app.server.Setup()
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

	return nil
}

// Stop stops all components.
func (app *Application) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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
