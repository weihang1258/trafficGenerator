package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/api/websocket"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
)

// WebSocketTestSuite WebSocket 集成测试套件
type WebSocketTestSuite struct {
	suite.Suite
	server *rest.Server
	engine *core.Engine
	db     *storage.DB
	wsHub  *websocket.Hub
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
			DSN:  ":memory:",
		},
		Engine: config.EngineConfig{
			ConfigWorkers:  2,
			PacketWorkers:  2,
			OutputWorkers:  2,
			BufferSize:     100,
			QueueSize:      10,
			MaxBufferBytes: 1024 * 1024,
		},
	}

	db, err := storage.NewDB(&cfg.Database)
	assert.NoError(suite.T(), err)
	suite.db = db

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  cfg.Engine.ConfigWorkers,
		PacketWorkers:  cfg.Engine.PacketWorkers,
		OutputWorkers:  cfg.Engine.OutputWorkers,
		BufferSize:     cfg.Engine.BufferSize,
		QueueSize:      cfg.Engine.QueueSize,
		MaxBufferBytes: cfg.Engine.MaxBufferBytes,
	})
	suite.engine = engine

	wsHub := websocket.NewHub()
	suite.wsHub = wsHub
	go wsHub.Run()

	wsHandler := websocket.NewHandler(wsHub)

	server := rest.NewServer(cfg, engine, wsHandler, db, nil)
	err = server.Setup()
	assert.NoError(suite.T(), err)
	suite.server = server

	err = engine.Start()
	assert.NoError(suite.T(), err)
}

// TearDownSuite 清理测试套件
func (suite *WebSocketTestSuite) TearDownSuite() {
	if suite.engine != nil {
		suite.engine.Stop()
	}
	if suite.db != nil {
		suite.db.Close()
	}
}

// TestWebSocketConnection 测试 WebSocket 连接
func (suite *WebSocketTestSuite) TestWebSocketConnection() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
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

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
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

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// 连接多个客户端
	conn1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn1.Close()

	conn2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn2.Close()

	// 等待连接建立
	time.Sleep(100 * time.Millisecond)

	// 验证连接数
	assert.Equal(suite.T(), 2, suite.wsHub.ClientCount())

	// 广播消息
	broadcastMsg := map[string]interface{}{
		"type":    "task_update",
		"task_id": "test-123",
		"status":  "running",
	}
	suite.wsHub.Broadcast(broadcastMsg)

	// 验证两个客户端都收到消息
	var response1, response2 map[string]interface{}

	err = conn1.ReadJSON(&response1)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "task_update", response1["type"])
	assert.Equal(suite.T(), "test-123", response1["task_id"])

	err = conn2.ReadJSON(&response2)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "task_update", response2["type"])
	assert.Equal(suite.T(), "test-123", response2["task_id"])
}

// TestWebSocketPingPong 测试 WebSocket 心跳
func (suite *WebSocketTestSuite) TestWebSocketPingPong() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
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

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	const clientCount = 5
	connections := make([]*websocket.Conn, clientCount)

	// 连接多个客户端
	for i := 0; i < clientCount; i++ {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
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

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
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

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn.Close()

	// 发送大消息（接近 64KB）
	largeData := strings.Repeat("x", 60000)
	message := map[string]interface{}{
		"type": "test",
		"data": largeData,
	}
	err = conn.WriteJSON(message)
	assert.NoError(suite.T(), err)

	// 读取响应
	var response map[string]interface{}
	err = conn.ReadJSON(&response)
	assert.NoError(suite.T(), err)
}

// TestWebSocketConcurrentMessages 测试并发消息
func (suite *WebSocketTestSuite) TestWebSocketConcurrentMessages() {
	server := httptest.NewServer(suite.server.Router())
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(suite.T(), err)
	defer conn.Close()

	// 并发发送消息
	const messageCount = 10
	done := make(chan bool, messageCount)

	for i := 0; i < messageCount; i++ {
		go func(id int) {
			msg := map[string]interface{}{
				"type": "test",
				"id":   id,
			}
			err := conn.WriteJSON(msg)
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
