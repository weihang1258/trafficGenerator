package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// APITestSuite API 集成测试套件
type APITestSuite struct {
	suite.Suite
	server   *rest.Server
	engine   *core.Engine
	db       *storage.DB
	authToken string
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
	}

	// 直接创建数据库连接，避免AutoMigrate问题
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), gormConfig)
	assert.NoError(suite.T(), err)

	// 手动创建表
	err = db.Exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, strategy_ids TEXT, output_type TEXT, output_config TEXT, flow_control TEXT, status TEXT NOT NULL, progress REAL DEFAULT 0, error_message TEXT, created_at DATETIME, updated_at DATETIME, started_at DATETIME, completed_at DATETIME)").Error
	assert.NoError(suite.T(), err)

	err = db.Exec("CREATE TABLE strategies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, protocol TEXT NOT NULL, config TEXT, flow_control TEXT, config_hash TEXT UNIQUE, created_at DATETIME, updated_at DATETIME)").Error
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

	// 初始化引擎
	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers: cfg.Engine.ConfigWorkers,
		PacketWorkers: cfg.Engine.PacketWorkers,
		OutputWorkers: cfg.Engine.OutputWorkers,
		BufferSize:    cfg.Engine.BufferSize,
		QueueSize:     cfg.Engine.QueueSize,
	})
	suite.engine = engine

	// 初始化服务器
	server := rest.NewServer(cfg, engine, nil, suite.db, nil)
	err = server.Setup()
	assert.NoError(suite.T(), err)
	suite.server = server

	// 启动引擎
	err = engine.Start()
	assert.NoError(suite.T(), err)

	// 创建测试用户并获取token
	suite.createTestUserAndToken()
}

func (suite *APITestSuite) createTestUserAndToken() {
	// 注册测试用户
	registerBody := map[string]string{
		"username": "testuser",
		"password": "testpass123",
		"email":    "test@example.com",
	}
	body, _ := json.Marshal(registerBody)
	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		suite.T().Fatalf("Failed to register user: status=%d, body=%s", w.Code, w.Body.String())
	}

	// 登录获取token
	loginBody := map[string]string{
		"username": "testuser",
		"password": "testpass123",
	}
	body, _ = json.Marshal(loginBody)
	req = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		suite.T().Fatalf("Failed to login: status=%d, body=%s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		suite.T().Fatalf("Failed to parse login response: %v", err)
	}

	// 从data字段中获取token（小写）
	data, ok := response["data"].(map[string]interface{})
	if !ok {
		suite.T().Fatalf("Login response missing 'data' field: %v", response)
	}

	token, ok := data["token"].(string)
	if !ok {
		suite.T().Fatalf("Login response data missing 'token' field: %v", data)
	}

	suite.authToken = token
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
	// 先创建策略
	strategyReq := map[string]interface{}{
		"name":      "test-strategy",
		"protocol":  "tcp",
		"config":    map[string]interface{}{},
		"flow_control": map[string]interface{}{"type": "flows", "value": 1},
	}
	body, _ := json.Marshal(strategyReq)
	req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w := httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	var strategyResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &strategyResp)
	strategyID := strategyResp["id"].(string)

	// 创建任务
	taskReq := map[string]interface{}{
		"name":         "test-task",
		"strategy_ids": []string{strategyID},
		"output_type":  "pcap",
		"output_config": map[string]interface{}{"pcap_path": "/tmp/test.pcap"},
	}

	body, _ = json.Marshal(taskReq)
	req = httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w = httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), response["id"])
}

// TestListTasks 测试获取任务列表接口
func (suite *APITestSuite) TestListTasks() {
	req := httptest.NewRequest("GET", "/api/v1/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response []interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
}

// TestGetTask 测试获取任务详情接口
func (suite *APITestSuite) TestGetTask() {
	// 先创建策略
	strategyReq := map[string]interface{}{
		"name":      "test-strategy-get",
		"protocol":  "udp",
		"config":    map[string]interface{}{},
		"flow_control": map[string]interface{}{"type": "flows", "value": 1},
	}
	body, _ := json.Marshal(strategyReq)
	req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w := httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	var strategyResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &strategyResp)
	strategyID := strategyResp["id"].(string)

	// 创建任务
	taskReq := map[string]interface{}{
		"name":         "test-task-detail",
		"strategy_ids": []string{strategyID},
		"output_type":  "pcap",
		"output_config": map[string]interface{}{"pcap_path": "/tmp/test.pcap"},
	}

	body, _ = json.Marshal(taskReq)
	req = httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w = httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	var createResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResponse)
	taskID := createResponse["id"].(string)

	// 获取任务详情
	req = httptest.NewRequest("GET", "/api/v1/tasks/"+taskID, nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w = httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), taskID, response["id"])
}

// TestDeleteTask 测试删除任务接口
func (suite *APITestSuite) TestDeleteTask() {
	// 先创建策略
	strategyReq := map[string]interface{}{
		"name":      "test-strategy-del",
		"protocol":  "tcp",
		"config":    map[string]interface{}{},
		"flow_control": map[string]interface{}{"type": "flows", "value": 1},
	}
	body, _ := json.Marshal(strategyReq)
	req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w := httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	var strategyResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &strategyResp)
	strategyID := strategyResp["id"].(string)

	// 创建任务
	taskReq := map[string]interface{}{
		"name":         "test-task-delete",
		"strategy_ids": []string{strategyID},
		"output_type":  "pcap",
		"output_config": map[string]interface{}{"pcap_path": "/tmp/test.pcap"},
	}

	body, _ = json.Marshal(taskReq)
	req = httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w = httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	var createResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResponse)
	taskID := createResponse["id"].(string)

	// 删除任务
	req = httptest.NewRequest("DELETE", "/api/v1/tasks/"+taskID, nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w = httptest.NewRecorder()
	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
}

// TestCreateStrategy 测试创建策略接口
func (suite *APITestSuite) TestCreateStrategy() {
	strategyReq := map[string]interface{}{
		"name":        "test-strategy",
		"protocol":    "tcp",
		"config":      map[string]interface{}{},
		"flow_control": map[string]interface{}{"type": "flows", "value": 1},
	}

	body, _ := json.Marshal(strategyReq)
	req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), response["id"])
}

// TestListStrategies 测试获取策略列表接口
func (suite *APITestSuite) TestListStrategies() {
	req := httptest.NewRequest("GET", "/api/v1/strategies", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
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
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response []interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
}

// TestGetBufferStatus 测试获取缓冲区状态接口
func (suite *APITestSuite) TestGetBufferStatus() {
	req := httptest.NewRequest("GET", "/api/v1/system/stats", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	w := httptest.NewRecorder()

	suite.server.Router().ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
}

// TestAPIIntegration 运行集成测试套件
func TestAPIIntegration(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}
