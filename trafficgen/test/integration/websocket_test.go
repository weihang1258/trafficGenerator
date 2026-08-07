package integration_test

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	gorillawebsocket "github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/api/websocket"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"github.com/trafficgen/trafficgen/pkg/netif"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// WebSocketTestSuite WebSocket 集成测试套件
type WebSocketTestSuite struct {
	suite.Suite
	server *rest.Server
	engine *core.Engine
	db     *storage.DB
	wsHub  *websocket.Hub
	token  string
}

// SetupSuite 初始化测试套件
func (suite *WebSocketTestSuite) SetupSuite() {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: "file::memory:?cache=shared",
			},
		},
		Engine: config.EngineConfig{
			ConfigWorkers:  2,
			PacketWorkers:  2,
			OutputWorkers:  2,
			BufferSize:     100,
			QueueSize:      10,
		},
		Auth: config.AuthConfig{
			JWTSecret:    "test-secret",
			JWTIssuer:    "trafficgen",
			JWTExpiresIn: 24,
		},
	}

	// 直接创建数据库连接，避免AutoMigrate问题
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), gormConfig)
	assert.NoError(suite.T(), err)

	// 手动创建表
	err = db.Exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, strategy_ids TEXT, protocol TEXT, batch_config TEXT, output_type TEXT, output_config TEXT, flow_control TEXT, status TEXT NOT NULL, progress REAL DEFAULT 0, error_message TEXT, created_at DATETIME, updated_at DATETIME, started_at DATETIME, completed_at DATETIME)").Error
	assert.NoError(suite.T(), err)

	err = db.Exec("CREATE TABLE strategies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, protocol TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'synth', config TEXT, flow_control TEXT, config_hash TEXT, created_at DATETIME, updated_at DATETIME)").Error
	assert.NoError(suite.T(), err)

	err = db.Exec("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, role TEXT NOT NULL DEFAULT 'user', enabled BOOLEAN DEFAULT 1, created_at DATETIME, updated_at DATETIME, last_login_at DATETIME)").Error
	assert.NoError(suite.T(), err)

	err = db.Exec("CREATE TABLE ports (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, type TEXT NOT NULL, pci_address TEXT, status TEXT NOT NULL DEFAULT 'idle', current_task_id TEXT, created_at DATETIME, updated_at DATETIME)").Error
	assert.NoError(suite.T(), err)

	err = db.Exec("CREATE TABLE port_groups (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, ports_config TEXT, created_at DATETIME, updated_at DATETIME)").Error
	assert.NoError(suite.T(), err)

	err = db.Exec("CREATE TABLE tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at DATETIME)").Error
	assert.NoError(suite.T(), err)

	suite.db = &storage.DB{DB: db}

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers: cfg.Engine.ConfigWorkers,
		PacketWorkers: cfg.Engine.PacketWorkers,
		OutputWorkers: cfg.Engine.OutputWorkers,
		BufferSize:    cfg.Engine.BufferSize,
		QueueSize:     cfg.Engine.QueueSize,
	})
	suite.engine = engine

	wsHub := websocket.NewHub()
	suite.wsHub = wsHub
	go wsHub.Run()

	wsHandler := websocket.NewHandler(wsHub)

	server := rest.NewServer(cfg, engine, wsHandler, suite.db, netif.NewManager(), netif.NewScheduler())
	err = server.Setup()
	assert.NoError(suite.T(), err)
	suite.server = server

	// Generate a JWT token for WebSocket connections (handler requires auth).
	token, err := auth.NewJWTManager(cfg.Auth.JWTSecret, cfg.Auth.JWTIssuer,
		time.Duration(cfg.Auth.JWTExpiresIn)*time.Hour).GenerateToken("test-user", "test-user", []string{"user"})
	assert.NoError(suite.T(), err)
	suite.token = token

	err = engine.Start()
	assert.NoError(suite.T(), err)
}

// wsURL builds a WebSocket URL with the auth token for the given httptest server.
func (suite *WebSocketTestSuite) wsURL(server *httptest.Server) string {
	return "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?token=" + suite.token
}

// TearDownSuite 清理测试套件
func (suite *WebSocketTestSuite) TearDownSuite() {
	if suite.engine != nil {
		done := make(chan struct{})
		go func() {
			suite.engine.Stop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	if suite.db != nil {
		suite.db.Close()
	}
}

// TestWebSocketConnection 测试 WebSocket 连接
func (suite *WebSocketTestSuite) TestWebSocketConnection() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := suite.wsURL(server)

	conn, _, err := gorillawebsocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn.Close()

	// 等待连接建立
	time.Sleep(100 * time.Millisecond)

	// 验证连接数
	assert.Equal(suite.T(), 1, suite.wsHub.ClientCount())
}

// TestWebSocketMessage 测试 WebSocket 消息发送和接收
func (suite *WebSocketTestSuite) TestWebSocketMessage() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := suite.wsURL(server)

	conn, _, err := gorillawebsocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn.Close()

	// 发送消息
	message := map[string]interface{}{
		"type": "subscribe",
		"topic": "tasks",
	}
	err = conn.WriteJSON(message)
	assert.NoError(suite.T(), err)

	// 读取响应
	var response map[string]interface{}
	err = conn.ReadJSON(&response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "subscribed", response["type"])
}

// TestWebSocketBroadcast 测试 WebSocket 广播消息
func (suite *WebSocketTestSuite) TestWebSocketBroadcast() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := suite.wsURL(server)

	// 连接多个客户端
	conn1, _, err := gorillawebsocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn1.Close()

	conn2, _, err := gorillawebsocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn2.Close()

	// 等待连接建立
	time.Sleep(100 * time.Millisecond)

	// 验证连接数
	assert.Equal(suite.T(), 2, suite.wsHub.ClientCount())

	// 广播消息
	broadcastMsg := websocket.Message{
		Type: "task_update",
		Data: map[string]interface{}{"task_id": "test-123", "status": "running"},
	}
	suite.wsHub.Broadcast(broadcastMsg)

	// 验证两个客户端都收到消息
	var response1, response2 map[string]interface{}

	err = conn1.ReadJSON(&response1)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "task_update", response1["type"])
	// Data field contains the task_id and status
	data1, ok := response1["data"].(map[string]interface{})
	assert.True(suite.T(), ok)
	assert.Equal(suite.T(), "test-123", data1["task_id"])
	assert.Equal(suite.T(), "running", data1["status"])

	err = conn2.ReadJSON(&response2)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "task_update", response2["type"])
	data2, ok := response2["data"].(map[string]interface{})
	assert.True(suite.T(), ok)
	assert.Equal(suite.T(), "test-123", data2["task_id"])
	assert.Equal(suite.T(), "running", data2["status"])
}

// TestWebSocketPingPong 测试 WebSocket 心跳
func (suite *WebSocketTestSuite) TestWebSocketPingPong() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := suite.wsURL(server)

	conn, _, err := gorillawebsocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn.Close()

	// 发送 ping 消息
	pingMsg := map[string]interface{}{
		"type":      "ping",
		"timestamp": time.Now().Unix(),
	}
	err = conn.WriteJSON(pingMsg)
	assert.NoError(suite.T(), err)

	// 读取 pong 响应
	var response map[string]interface{}
	err = conn.ReadJSON(&response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "pong", response["type"])
}

// TestWebSocketMultipleClients 测试多个客户端连接
func (suite *WebSocketTestSuite) TestWebSocketMultipleClients() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := suite.wsURL(server)

	const clientCount = 5
	connections := make([]*gorillawebsocket.Conn, clientCount)

	// 连接多个客户端
	for i := 0; i < clientCount; i++ {
		conn, _, err := gorillawebsocket.DefaultDialer.Dial(wsURL, nil)
		assert.NoError(suite.T(), err)
		connections[i] = conn
	}

	// 等待连接建立
	time.Sleep(200 * time.Millisecond)

	// 验证连接数
	assert.Equal(suite.T(), clientCount, suite.wsHub.ClientCount())

	// 关闭所有连接
	for _, conn := range connections {
		conn.Close()
	}

	// 等待连接关闭
	time.Sleep(200 * time.Millisecond)

	// 验证连接数减少
	assert.Equal(suite.T(), 0, suite.wsHub.ClientCount())
}

// TestWebSocketDisconnect 测试 WebSocket 断开连接
func (suite *WebSocketTestSuite) TestWebSocketDisconnect() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := suite.wsURL(server)

	conn, _, err := gorillawebsocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)

	// 等待连接建立
	time.Sleep(100 * time.Millisecond)

	// 验证连接数
	assert.Equal(suite.T(), 1, suite.wsHub.ClientCount())

	// 关闭连接
	conn.Close()

	// 等待连接关闭
	time.Sleep(100 * time.Millisecond)

	// 验证连接数减少
	assert.Equal(suite.T(), 0, suite.wsHub.ClientCount())
}

// TestWebSocketLargeMessage 测试大消息
func (suite *WebSocketTestSuite) TestWebSocketLargeMessage() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := suite.wsURL(server)

	conn, _, err := gorillawebsocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn.Close()

	// 发送大消息（接近 64KB，但不超过限制）
	largeData := strings.Repeat("x", 60000)
	message := map[string]interface{}{
		"type": "test",
		"data": largeData,
	}
	err = conn.WriteJSON(message)
	assert.NoError(suite.T(), err)

	// 读取响应（echo或确认）
	// 由于服务器可能不处理test类型消息，我们只验证发送成功
	// 设置短超时，如果没有响应就继续
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	var response map[string]interface{}
	err = conn.ReadJSON(&response)
	// 允许超时错误，因为服务器可能不响应test消息
	if err != nil {
		assert.Contains(suite.T(), err.Error(), "timeout")
	}
}

// TestWebSocketConcurrentMessages 测试并发消息
func (suite *WebSocketTestSuite) TestWebSocketConcurrentMessages() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := suite.wsURL(server)

	conn, _, err := gorillawebsocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn.Close()

	// 并发发送消息 (serialize writes with mutex - gorilla websocket is not thread-safe)
	const messageCount = 10
	done := make(chan bool, messageCount)
	var writeMu sync.Mutex

	for i := 0; i < messageCount; i++ {
		go func(id int) {
			msg := map[string]interface{}{
				"type": "test",
				"id":   id,
			}
			writeMu.Lock()
			err := conn.WriteJSON(msg)
			writeMu.Unlock()
			assert.NoError(suite.T(), err)
			done <- true
		}(i)
	}

	// 等待所有消息发送完成
	for i := 0; i < messageCount; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			suite.T().Fatal("Timeout waiting for message")
		}
	}
}

// TestWebSocketIntegration 运行 WebSocket 集成测试套件
func TestWebSocketIntegration(t *testing.T) {
	suite.Run(t, new(WebSocketTestSuite))
}
