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
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/mcp"
	"github.com/trafficgen/trafficgen/internal/output"
	_ "github.com/trafficgen/trafficgen/internal/protocol/a2a"
	_ "github.com/trafficgen/trafficgen/internal/protocol/arp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/bgp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/coap"
	_ "github.com/trafficgen/trafficgen/internal/protocol/cql"
	// 空导入：cwmp 包 init 反向注册终结层生成器 + 校验器（64-cwmp v2.1.1：
	// TR-069 over HTTP，[tcp→http→cwmp]，无空导入则二进制不含其 init，
	// ChainPlanner("cwmp") 实例化时 generator not implemented）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/cwmp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dhcp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dhcpv6"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dnp3"
	_ "github.com/trafficgen/trafficgen/internal/protocol/doip"
	_ "github.com/trafficgen/trafficgen/internal/protocol/enip"
	_ "github.com/trafficgen/trafficgen/internal/protocol/fins"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ftp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gbt32960"
	_ "github.com/trafficgen/trafficgen/internal/protocol/goose"
	// 空导入：gre 包 init 注册 gre 隧道层生成器 + 校验器（D-GRE-1 翻转）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/gre"
	_ "github.com/trafficgen/trafficgen/internal/protocol/igmp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/isis"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ospf"
	_ "github.com/trafficgen/trafficgen/internal/protocol/pim"
	// 空导入：grpc 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/grpc"
	// 空导入：gtp 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/gtp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/h323" // 空导入：h323 包 init 注册层生成器 + 校验器（D-H323-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/iec104"
	// 空导入：http 包 init 反向注册 http 层生成器（layers.RegisterHTTPGenerator），
	// ChainPlanner("http") 经此实例化；协议本体由层链驱动。
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
	// 空导入：http_flv 包 init 注册终结层生成器 + 校验器
	// （layers.RegisterLayerGenerator/RegisterLayerValidator）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/http_flv"
	// 空导入：hls 包 init 注册终结层生成器 + 校验器
	// （layers.RegisterLayerGenerator/RegisterLayerValidator，[ip→tcp→http→hls]
	// 链：hls 终结层产 playlist/segment/key body 事件，http 层 EventTransformer
	// 包装为 HTTP GET/响应帧）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/hls"
	// 空导入：hds 包 init 注册终结层生成器 + 校验器
	// （layers.RegisterLayerGenerator/RegisterLayerValidator，[ip→tcp→http→hds]
	// 链：hds 终结层产 F4M manifest/bootstrap/F4F fragment body 事件，http 层
	// EventTransformer 包装为 HTTP GET/响应帧）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/hds"
	// 空导入：dns/ntp/snmp/syslog 包 init 反向注册终结层生成器 + 校验器
	// （layers.RegisterLayerGenerator/RegisterLayerValidator，波 4）；波 5：
	// dhcp/dhcpv6/mdns/ssdp/rip 同机制接入公共 udp 层（init 注册
	// generator+validator）。无空导入则包不被链接进二进制，
	// ChainPlanner("dns") 实例化失败。
	_ "github.com/trafficgen/trafficgen/internal/protocol/cflow"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dameng"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dns"
	_ "github.com/trafficgen/trafficgen/internal/protocol/drda"
	_ "github.com/trafficgen/trafficgen/internal/protocol/icmp"   // 空导入：icmp 包 init 注册层生成器 + 校验器（D-ICMP-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/icmpv6" // 空导入：icmpv6 包 init 注册层生成器 + 校验器（D-ICMPV6-1）
	// 空导入：ike 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/ike"
	// 空导入：ike_nat_t 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/ike_nat_t"
	// 空导入：imap 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/imap"
	_ "github.com/trafficgen/trafficgen/internal/protocol/jt808"
	"github.com/trafficgen/trafficgen/internal/protocol/jt809"
	_ "github.com/trafficgen/trafficgen/internal/protocol/jt809"
	"github.com/trafficgen/trafficgen/internal/protocol/jtt905"
	_ "github.com/trafficgen/trafficgen/internal/protocol/jtt905"
	// 空导入：l2tp 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/ams"
	_ "github.com/trafficgen/trafficgen/internal/protocol/geneve"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gnutella"
	_ "github.com/trafficgen/trafficgen/internal/protocol/l2tp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ldap" // 空导入：ldap 包 init 注册层生成器 + 校验器（D-LDAP-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/ldp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mcp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mdns"
	_ "github.com/trafficgen/trafficgen/internal/protocol/megaco" // init 注册 megaco 终结层生成器+校验器（D-MEGACO-1，RFC 3525 文本编码）
	_ "github.com/trafficgen/trafficgen/internal/protocol/mms"
	_ "github.com/trafficgen/trafficgen/internal/protocol/modbus"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mongodb"
	_ "github.com/trafficgen/trafficgen/internal/protocol/moxa"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mpls" // 空导入：mpls 包 init 注册层生成器 + 校验器（D-MPLS-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/mqtt"
	_ "github.com/trafficgen/trafficgen/internal/protocol/nvgre"
	_ "github.com/trafficgen/trafficgen/internal/protocol/openwire"
	_ "github.com/trafficgen/trafficgen/internal/protocol/swarm"
	_ "github.com/trafficgen/trafficgen/internal/protocol/vxlan"
	// 空导入：mysql 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/mysql"
	_ "github.com/trafficgen/trafficgen/internal/protocol/nfs"
	// 空导入：ngap 包 init 注册层生成器 + 校验器（D-NGAP-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/ngap"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ntp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/opcua"
	// 空导入：openvpn 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/openvpn"
	_ "github.com/trafficgen/trafficgen/internal/protocol/pcep"
	// 空导入：pop3 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/pop3"
	_ "github.com/trafficgen/trafficgen/internal/protocol/postgresql" // init 注册 postgresql 层生成器 + 校验器（kingbase 是其 dialect 变体）
	_ "github.com/trafficgen/trafficgen/internal/protocol/pppoe"
	_ "github.com/trafficgen/trafficgen/internal/protocol/pptp" // 空导入：pptp 包 init 注册层生成器 + 校验器（D-PPTP-1）
	// 空导入：radius 包 init 注册层生成器 + 校验器（D-RADIUS-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/radius"
	// 空导入：rdp 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/rdp"
	// 空导入：redis 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/redis"
	_ "github.com/trafficgen/trafficgen/internal/protocol/rip"
	_ "github.com/trafficgen/trafficgen/internal/protocol/rtmp" // 空导入：rtmp 包 init 注册层生成器 + 校验器（D-RTMP-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/rtsp" // 空导入：rtsp 包 init 注册层生成器 + 校验器（D-RTSP-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/s7"
	// 空导入：sctp 包 init 注册层生成器 + 校验器（D-SCTP-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/sctp"
	// 空导入：shadowsocks 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/shadowsocks"
	// 空导入：sip 包 init 注册层生成器 + 校验器（D-SIP-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/sip"
	_ "github.com/trafficgen/trafficgen/internal/protocol/smb"
	// 空导入：smtp 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/smtp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/snmp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/socks5"
	_ "github.com/trafficgen/trafficgen/internal/protocol/someip"
	_ "github.com/trafficgen/trafficgen/internal/protocol/srv6"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ssdp"
	// 空导入：ssh 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/ssh"
	_ "github.com/trafficgen/trafficgen/internal/protocol/sv"
	_ "github.com/trafficgen/trafficgen/internal/protocol/syslog"
	_ "github.com/trafficgen/trafficgen/internal/protocol/thrift"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tns"
	// 空导入：stun 包 init 反向注册终结层生成器 + 校验器
	// （layers.RegisterLayerGenerator/RegisterLayerValidator）。无空导入则包
	// 不被链接进二进制，ChainPlanner("stun") 实例化失败。
	_ "github.com/trafficgen/trafficgen/internal/protocol/amqp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/rtmfp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/stun"
	// 空导入：gbt 包 init 反向注册终结层生成器 + 校验器（B6：BIP 22/23
	// JSON-RPC over HTTP，[ip→tcp→http→gbt] 链，http 层透传转发）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/gbt"
	// 空导入：getwork 包 init 反向注册终结层生成器 + 校验器（B6：Bitcoin
	// legacy getwork JSON-RPC over HTTP，[ip→tcp→http→getwork] 链，同款透传
	// 转发）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/getwork"
	// 空导入：stratum 包 init 反向注册终结层生成器 + 校验器（B6：比特币
	// Stratum v1，[tcp→stratum] 行式 JSON 直连，无 http 层）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/stratum"
	// 空导入：ethmining 包 init 反向注册终结层生成器 + 校验器（73-ethmining
	// v2.0.2：以太 ethash stratum 行式 JSON 直连 [tcp→ethmining]）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/ethmining"
	// 空导入：nmea 包 init 反向注册终结层生成器 + 校验器（69-nmea v2.0.0：
	// NMEA 0183 sentence 明文，[tcp→nmea]/[udp→nmea] 双载体）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/nmea"
	// 空导入：doh 包 init 反向注册终结层生成器 + 校验器（66-doh v2.2.1：
	// DNS over HTTPS / RFC 8484，[tcp→http→doh] 明文 HTTP/1.1 主 profile）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/doh"
	// 空导入：onvif 包 init 反向注册终结层生成器 + 校验器（67-onvif v2.1.1：
	// ONVIF Core Spec Ver. 26.06 SOAP 1.2 over HTTP，[tcp→http→onvif]
	// 明文 HTTP/1.1 主 profile）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/onvif"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tds"
	// 空导入：telnet 包 init 注册层生成器 + 校验器（D-TELNET-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/telnet"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tftp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tls"
	// 空导入：vmess 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/vmess"
	// 空导入：vnc 包 init 注册层生成器 + 校验器（D-VNC-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/vnc"
	// 空导入：wireguard 包 init 注册终结层生成器 + 校验器（T4.1 批二）
	_ "github.com/trafficgen/trafficgen/internal/protocol/wireguard"
	// 空导入：xmpp 包 init 注册层生成器 + 校验器（D-XMPP-1）
	_ "github.com/trafficgen/trafficgen/internal/protocol/xmpp"
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

	// Register protocol planners directly to engine.
	// tcp 走层链规划器（方案 C 分层配置 P2a 波 1）：类名 tcp → 层链 [ip, tcp]，
	// 公共 ip/tcp 层生成器驱动；字节级兼容旧 tcp planner（SYN 选项/窗口/seq 推进）。
	app.engine.RegisterPlanner(layers.NewChainPlanner("tcp"))
	// udp 切链式生成器（波 3）：[ip→udp] 层链驱动，UDPGenerator 字节级兼容
	// legacy udp planner（request + 可选 response，disable_checksum 经
	// FlowMeta.UDP 传播）；事件模型泛化为 MessageEvent，dns/ntp 等终结层
	// 后续接线。
	app.engine.RegisterPlanner(layers.NewChainPlanner("udp"))
	// http 切链式生成器（波 2 方案 A）：[ip→tcp→http] 层链驱动，报文事件流
	// 经 tcp 层分段，字节与 legacy http.go 一致（126 个 legacy 测试直接调
	// NewPlanner().Plan 保留回归）。http 包 init 反向注册 http 层生成器。
	app.engine.RegisterPlanner(layers.NewChainPlanner("http"))
	// http_flv 切链式生成器（[ip→tcp→http→http_flv] 层链驱动）：http_flv 终结
	// 层生成 FLV body 事件，http 层 EventTransformer 包装为 HTTP GET/200 帧，
	// tcp 层分段。http_flv 包 init 反向注册终结层生成器 + 校验器。
	app.engine.RegisterPlanner(layers.NewChainPlanner("http_flv"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("hls"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("hds"))
	// dns/ntp/snmp/syslog 切链式生成器（波 4）：[ip→udp→dns/ntp/snmp/syslog]
	// 层链驱动，各协议包 init 反向注册终结层生成器 + 校验器，事件字节复用
	// legacy 编码器，字节级兼容旧 planner；chain 校验器拒绝 dns tcp /
	// syslog tcp/tls（与 legacy 握手语义不同，暂缓）。
	app.engine.RegisterPlanner(layers.NewChainPlanner("coap"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("s7"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("iec104"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("bgp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("opcua"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("vxlan"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("nvgre"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("geneve"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("openwire"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ams"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("swarm"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("gnutella"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("mms"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("moxa"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("drda"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("thrift"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("tns"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("mongodb"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("dameng"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("postgresql")) // 共享 PG v3 wire 层（kingbase 作 dialect 变体，不再独立注册）
	app.engine.RegisterPlanner(layers.NewChainPlanner("megaco"))     // D-MEGACO-1：RFC 3525 文本编码（udp/tcp 双载体，mgcp 别名 2427）
	app.engine.RegisterPlanner(layers.NewChainPlanner("cql"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("someip"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("stun"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("gbt"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("getwork"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("stratum"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ethmining"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("nmea"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("doh"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("onvif"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("rtmfp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("amqp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("cflow"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("dns"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ntp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("snmp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("syslog"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ldp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("pcep"))
	// mdns/ssdp/rip/dhcp/dhcpv6 切链式生成器（波 5a-5e）：[ip→udp→终结层]
	// 层链驱动，各协议包 init 反向注册终结层生成器 + 校验器，事件字节复用
	// legacy 编码器；多播覆盖经事件级 L2/L3 覆盖（OverrideDstIP/MAC + TTL），
	// dhcp/dhcpv6 端口按角色解析（L4PortOverride 免二次交换），字节级兼容
	// 旧 planner。
	app.engine.RegisterPlanner(layers.NewChainPlanner("mdns"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ssdp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("rip"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("dhcp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("dhcpv6"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("sv"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("goose"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("icmp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("arp"))
	// raw-IP 路由终结层（P3 T5）：igmp/ospf/pim 是 [ip,<proto>] 链（无 tcp/udp
	// 传输层，L3.Protocol=2/89/103 由 ChainPlanner 的 raw-IP 分支处理）；
	// isis 是 L2-only [eth,isis] LLC 链。
	app.engine.RegisterPlanner(layers.NewChainPlanner("igmp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ospf"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("pim"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("isis"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ftp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("sip"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("rtsp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("sctp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("icmpv6"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("smtp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("pop3"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("telnet"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("imap"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("grpc"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ssh"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ike"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ike_nat_t"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("l2tp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("pppoe"))
	// gre 切链式生成器（D-GRE-1：[ip→gre→ip→udp→dns] 隧道链驱动，gre 作
	// 真隧道层——内层包字节自建 + L2.GRE wire 配置 + 外层 proto 47；gre 包
	// init 反向注册隧道层生成器 + 校验器）。
	app.engine.RegisterPlanner(layers.NewChainPlanner("gre"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("mpls"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("gtp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("rdp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("radius"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ldap"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("vnc"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("pptp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("h323"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("rtmp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("redis"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("mysql"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("ngap"))
	// tls 切链式生成器（D-TLS-1：[ip→tcp→tls→http] 隧道链驱动，tls 作事件
	// 变换器（握手先行注入+内层事件包 record），TCP 握手/挥手/分段归 tcp 层；
	// tls 包 init 反向注册隧道层生成器 + 校验器）。
	app.engine.RegisterPlanner(layers.NewChainPlanner("tls"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("openvpn"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("shadowsocks"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("socks5"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("vmess"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("wireguard"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("xmpp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("mqtt"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("srv6"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("gbt32960"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("tftp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("jt808"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("jt809"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("jtt905"))
	app.engine.RegisterPlanner(jt809.NewPlanner())
	app.engine.RegisterPlanner(jtt905.NewPlanner())
	app.engine.RegisterPlanner(layers.NewChainPlanner("doip"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("smb"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("nfs"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("fins"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("tds"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("enip"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("modbus"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("dnp3"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("mcp"))
	app.engine.RegisterPlanner(layers.NewChainPlanner("a2a"))

	// P2c 层链驱动生成: inject the layer-planner factory so tasks carrying a
	// "layers" config get a per-task ChainPlanner at submit time. core cannot
	// import layers (layers imports core), so the wiring lives here, where
	// both packages are imported.
	app.engine.SetLayerPlannerFactory(layers.BuildLayersPlanner)

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

// initServer initializes the API server. After construction, the filesystem
// is wired in before Setup() so the /api/v1/fs/* routes are registered.
// Guarded by nil check to mirror the MCP pattern: when filesystem init
// failed at engine startup, routes are simply not registered and the
// handler returns "filesystem not configured" rather than nil-derefing.
func (app *Application) initServer() error {
	app.server = rest.NewServer(app.config, app.engine, app.wsHandler, app.db, app.ifaceMgr, app.portSched)
	if app.filesystem != nil {
		app.server.SetFilesystem(app.filesystem)
	}
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
	// Filesystem is needed by flowb_manage_filesystem (upload/read/delete/
	// mkdir/rmdir/list/query). When app.filesystem is nil (e.g. filesystem
	// init failed at engine startup), the tool is not registered and the
	// handler returns "filesystem not configured" -- so the LLM gets a
	// clear error rather than a nil-deref. The nil guard inside
	// registerFilesystemTool also protects the test path (setupMCPTest
	// never wires a filesystem).
	if app.filesystem != nil {
		srv.SetFilesystem(app.filesystem)
	}
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
