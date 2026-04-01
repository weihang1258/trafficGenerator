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
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol"
	"github.com/trafficgen/trafficgen/internal/protocol/dns"
	"github.com/trafficgen/trafficgen/internal/protocol/http"
	"github.com/trafficgen/trafficgen/internal/protocol/icmp"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/logger"
	"go.uber.org/zap"
)

var (
	configPath = flag.String("config", "", "Path to configuration file")
	version    = "1.0.0"
)

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

	// Create engine
	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  cfg.Engine.ConfigWorkers,
		PacketWorkers:  cfg.Engine.PacketWorkers,
		OutputWorkers:  cfg.Engine.OutputWorkers,
		BufferSize:     cfg.Engine.BufferSize,
		QueueSize:      cfg.Engine.QueueSize,
		MaxBufferBytes: 100 * 1024 * 1024, // 100MB
	})

	// Register protocol planners
	registerProtocols()

	// Set packet builder
	builder := core.NewBuilder()
	engine.SetBuildFunc(builder.Build)

	// Start engine
	if err := engine.Start(); err != nil {
		zap.L().Fatal("failed to start engine", zap.Error(err))
	}
	defer engine.Stop()

	// Create API server
	server := rest.NewServer(cfg, engine)
	if err := server.Setup(); err != nil {
		zap.L().Fatal("failed to setup server", zap.Error(err))
	}

	// Start server in goroutine
	go func() {
		zap.L().Info("starting HTTP server",
			zap.String("host", cfg.Server.Host),
			zap.Int("port", cfg.Server.Port),
		)
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			zap.L().Fatal("server error", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	zap.L().Info("shutting down...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		zap.L().Error("server shutdown error", zap.Error(err))
	}

	zap.L().Info("server stopped")
}

// registerProtocols registers all protocol planners.
func registerProtocols() {
	protocol.Register(tcp.NewPlanner())
	protocol.Register(udp.NewPlanner())
	protocol.Register(http.NewPlanner())
	protocol.Register(dns.NewPlanner())
	protocol.Register(icmp.NewPlanner())

	zap.L().Info("protocols registered",
		zap.Strings("protocols", protocol.List()),
	)
}
