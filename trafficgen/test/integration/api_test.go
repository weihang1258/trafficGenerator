package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
)

// APITestSuite API 集成测试套件
type APITestSuite struct {
	suite.Suite
	server *rest.Server
	engine *core.Engine
	db     *storage.DB
}

// SetupSuite 初始化测试套件
func (suite *APITestSuite) SetupSuite() {
	// 加载配置
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

	// 初始化数据库
	db, err := storage.NewDB(&cfg.Database)
	assert.NoError(suite.T(), err)
	suite.db = db

	// 初始化引擎
	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers:  cfg.Engine.ConfigWorkers,
		PacketWorkers:  cfg.Engine.PacketWorkers,
		OutputWorkers:  cfg.Engine.OutputWorkers,
		BufferSize:     cfg.Engine.BufferSize,
		QueueSize:      cfg.Engine.QueueSize,
		MaxBufferBytes: cfg.Engine.MaxBufferBytes,
	})
	suite.engine = engine

	// 初始化服务器
	server := rest.NewServer(cfg, engine, nil, db, nil)
	err = server.Setup()
	assert.NoError(suite.T(), err)
	suite.server = server

	// 启动引擎
	err = engine.Start()
	assert.NoError(suite.T(), err)
}

// TearDownSuite 清理测试套件
func (suite *APITestSuite) TearDownSuite() {
	if suite.engine != nil {
		suite.engine.Stop()
	}
	if suite.db != nil {
		suite.db.Close()
	}
}

// TestHealthEndpoint 测试健康检查接口
func (suite *APITestSuite) TestHealthEndpoint() {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "healthy", response["status"])
}

// TestCreateTask 测试创建任务接口
func (suite *APITestSuite) TestCreateTask() {
	taskReq := map[string]interface{}{
		"name":     "test-task",
		"protocol": "tcp",
		"config": map[string]interface{}{
			"src_ip":   "192.168.1.1",
			"dst_ip":   "192.168.1.2",
			"src_port": 12345,
			"dst_port": 80,
		},
	}

	body, _ := json.Marshal(taskReq)
	req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), response["id"])
	assert.Equal(suite.T(), "test-task", response["name"])
	assert.Equal(suite.T(), "tcp", response["protocol"])
	assert.Equal(suite.T(), "pending", response["status"])
}

// TestListTasks 测试获取任务列表接口
func (suite *APITestSuite) TestListTasks() {
	req := httptest.NewRequest("GET", "/api/v1/tasks", nil)
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response, "tasks")
	assert.Contains(suite.T(), response, "total")
}

// TestGetTask 测试获取任务详情接口
func (suite *APITestSuite) TestGetTask() {
	// 先创建一个任务
	taskReq := map[string]interface{}{
		"name":     "test-task-detail",
		"protocol": "udp",
		"config": map[string]interface{}{
			"src_ip":   "192.168.1.1",
			"dst_ip":   "192.168.1.2",
			"src_port": 12345,
			"dst_port": 53,
		},
	}

	body, _ := json.Marshal(taskReq)
	req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	var createResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResponse)
	taskID := createResponse["id"].(string)

	// 获取任务详情
	req = httptest.NewRequest("GET", "/api/v1/tasks/"+taskID, nil)
	w = httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), taskID, response["id"])
	assert.Equal(suite.T(), "test-task-detail", response["name"])
}

// TestDeleteTask 测试删除任务接口
func (suite *APITestSuite) TestDeleteTask() {
	// 先创建一个任务
	taskReq := map[string]interface{}{
		"name":     "test-task-delete",
		"protocol": "tcp",
		"config": map[string]interface{}{
			"src_ip":   "192.168.1.1",
			"dst_ip":   "192.168.1.2",
			"src_port": 12345,
			"dst_port": 80,
		},
	}

	body, _ := json.Marshal(taskReq)
	req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	var createResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResponse)
	taskID := createResponse["id"].(string)

	// 删除任务
	req = httptest.NewRequest("DELETE", "/api/v1/tasks/"+taskID, nil)
	w = httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// 验证任务已删除
	req = httptest.NewRequest("GET", "/api/v1/tasks/"+taskID, nil)
	w = httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusNotFound, w.Code)
}

// TestCreateStrategy 测试创建策略接口
func (suite *APITestSuite) TestCreateStrategy() {
	strategyReq := map[string]interface{}{
		"name":        "test-strategy",
		"description": "Test strategy description",
		"config": map[string]interface{}{
			"protocol": "tcp",
			"src_ip":   "192.168.1.1",
			"dst_ip":   "192.168.1.2",
		},
	}

	body, _ := json.Marshal(strategyReq)
	req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), response["id"])
	assert.Equal(suite.T(), "test-strategy", response["name"])
}

// TestListStrategies 测试获取策略列表接口
func (suite *APITestSuite) TestListStrategies() {
	req := httptest.NewRequest("GET", "/api/v1/strategies", nil)
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response []interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
}

// TestGetInterfaces 测试获取网卡列表接口
func (suite *APITestSuite) TestGetInterfaces() {
	req := httptest.NewRequest("GET", "/api/v1/interfaces", nil)
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response []interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
}

// TestGetBufferStatus 测试获取缓冲区状态接口
func (suite *APITestSuite) TestGetBufferStatus() {
	req := httptest.NewRequest("GET", "/api/v1/buffer/status", nil)
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response, "combined")
}

// TestAPIIntegration 运行集成测试套件
func TestAPIIntegration(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}
