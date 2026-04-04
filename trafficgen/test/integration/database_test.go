package integration_test

import (
	"fmt"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DatabaseTestSuite 数据库集成测试套件
type DatabaseTestSuite struct {
	suite.Suite
	db *storage.DB
}

// SetupSuite 初始化测试套件
func (suite *DatabaseTestSuite) SetupSuite() {
	// 直接创建数据库连接，不调用 NewDB 避免自动迁移
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	// 使用共享缓存的内存数据库以支持并发访问
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), gormConfig)
	assert.NoError(suite.T(), err)

	suite.db = &storage.DB{
		DB: db,
	}

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
}

// TearDownSuite 清理测试套件
func (suite *DatabaseTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
}

// TestCreateTask 测试创建任务
func (suite *DatabaseTestSuite) TestCreateTask() {
	task := &storage.TaskModel{
		ID:          "test-task-1",
		UserID:      "user-1",
		Name:        "test-task",
		StrategyIDs: `["strategy-1"]`,
		OutputType:  "pcap",
		Status:      "pending",
	}

	err := suite.db.Create(task).Error
	assert.NoError(suite.T(), err)
	assert.NotZero(suite.T(), task.ID)
}

// TestGetTask 测试获取任务
func (suite *DatabaseTestSuite) TestGetTask() {
	// 创建任务
	task := &storage.TaskModel{
		ID:          "test-task-2",
		UserID:      "user-1",
		Name:        "test-task-get",
		StrategyIDs: `["strategy-1"]`,
		OutputType:  "pcap",
		Status:      "pending",
	}
	err := suite.db.Create(task).Error
	assert.NoError(suite.T(), err)

	// 获取任务
	var retrievedTask storage.TaskModel
	err = suite.db.Where("id = ?", task.ID).First(&retrievedTask).Error
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), task.Name, retrievedTask.Name)
}

// TestUpdateTask 测试更新任务
func (suite *DatabaseTestSuite) TestUpdateTask() {
	// 创建任务
	task := &storage.TaskModel{
		ID:          "test-task-3",
		UserID:      "user-1",
		Name:        "test-task-update",
		StrategyIDs: `["strategy-1"]`,
		OutputType:  "pcap",
		Status:      "pending",
	}
	err := suite.db.Create(task).Error
	assert.NoError(suite.T(), err)

	// 更新任务
	task.Status = "running"
	err = suite.db.Save(task).Error
	assert.NoError(suite.T(), err)

	// 验证更新
	var retrievedTask storage.TaskModel
	err = suite.db.Where("id = ?", task.ID).First(&retrievedTask).Error
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "running", retrievedTask.Status)
}

// TestDeleteTask 测试删除任务
func (suite *DatabaseTestSuite) TestDeleteTask() {
	// 创建任务
	task := &storage.TaskModel{
		ID:          "test-task-4",
		UserID:      "user-1",
		Name:        "test-task-delete",
		StrategyIDs: `["strategy-1"]`,
		OutputType:  "pcap",
		Status:      "pending",
	}
	err := suite.db.Create(task).Error
	assert.NoError(suite.T(), err)

	// 删除任务
	err = suite.db.Delete(task).Error
	assert.NoError(suite.T(), err)

	// 验证删除
	var retrievedTask storage.TaskModel
	err = suite.db.Where("id = ?", task.ID).First(&retrievedTask).Error
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), gorm.ErrRecordNotFound, err)
}

// TestListTasks 测试列出任务
func (suite *DatabaseTestSuite) TestListTasks() {
	// 创建多个任务
	for i := 0; i < 5; i++ {
		task := &storage.TaskModel{
			ID:          string(rune('a' + i)),
			UserID:      "user-1",
			Name:        "test-task-list",
			StrategyIDs: `["strategy-1"]`,
			OutputType:  "pcap",
			Status:      "pending",
		}
		err := suite.db.Create(task).Error
		assert.NoError(suite.T(), err)
	}

	// 列出任务
	var tasks []storage.TaskModel
	err := suite.db.Where("user_id = ?", "user-1").Find(&tasks).Error
	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), len(tasks), 5)
}

// TestCreateStrategy 测试创建策略
func (suite *DatabaseTestSuite) TestCreateStrategy() {
	strategy := &storage.StrategyModel{
		ID:          "strategy-1",
		UserID:      "user-1",
		Name:        "test-strategy",
		Protocol:    "tcp",
		Config:      `{"src_ip":"192.168.1.1"}`,
		FlowControl: `{"type":"flows","value":1}`,
		ConfigHash:  "hash-1",
	}

	err := suite.db.Create(strategy).Error
	assert.NoError(suite.T(), err)
	assert.NotZero(suite.T(), strategy.ID)
}

// TestGetStrategy 测试获取策略
func (suite *DatabaseTestSuite) TestGetStrategy() {
	strategy := &storage.StrategyModel{
		ID:          "strategy-2",
		UserID:      "user-1",
		Name:        "test-strategy-get",
		Protocol:    "tcp",
		Config:      `{}`,
		FlowControl: `{"type":"flows","value":1}`,
		ConfigHash:  "hash-2",
	}
	err := suite.db.Create(strategy).Error
	assert.NoError(suite.T(), err)

	var retrievedStrategy storage.StrategyModel
	err = suite.db.Where("id = ?", strategy.ID).First(&retrievedStrategy).Error
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), strategy.Name, retrievedStrategy.Name)
}

// TestUpdateStrategy 测试更新策略
func (suite *DatabaseTestSuite) TestUpdateStrategy() {
	strategy := &storage.StrategyModel{
		ID:          "strategy-3",
		UserID:      "user-1",
		Name:        "test-strategy-update",
		Protocol:    "tcp",
		Config:      `{}`,
		FlowControl: `{"type":"flows","value":1}`,
		ConfigHash:  "hash-3",
	}
	err := suite.db.Create(strategy).Error
	assert.NoError(suite.T(), err)

	strategy.Name = "updated-strategy"
	err = suite.db.Save(strategy).Error
	assert.NoError(suite.T(), err)

	var retrievedStrategy storage.StrategyModel
	err = suite.db.Where("id = ?", strategy.ID).First(&retrievedStrategy).Error
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "updated-strategy", retrievedStrategy.Name)
}

// TestDeleteStrategy 测试删除策略
func (suite *DatabaseTestSuite) TestDeleteStrategy() {
	strategy := &storage.StrategyModel{
		ID:          "strategy-4",
		UserID:      "user-1",
		Name:        "test-strategy-delete",
		Protocol:    "tcp",
		Config:      `{}`,
		FlowControl: `{"type":"flows","value":1}`,
		ConfigHash:  "hash-4",
	}
	err := suite.db.Create(strategy).Error
	assert.NoError(suite.T(), err)

	err = suite.db.Delete(strategy).Error
	assert.NoError(suite.T(), err)

	var retrievedStrategy storage.StrategyModel
	err = suite.db.Where("id = ?", strategy.ID).First(&retrievedStrategy).Error
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), gorm.ErrRecordNotFound, err)
}

// TestListStrategies 测试列出策略
func (suite *DatabaseTestSuite) TestListStrategies() {
	for i := 0; i < 3; i++ {
		strategy := &storage.StrategyModel{
			ID:          string(rune('x' + i)),
			UserID:      "user-1",
			Name:        "test-strategy-list",
			Protocol:    "tcp",
			Config:      `{}`,
			FlowControl: `{"type":"flows","value":1}`,
			ConfigHash:  string(rune('m' + i)),
		}
		err := suite.db.Create(strategy).Error
		assert.NoError(suite.T(), err)
	}

	var strategies []storage.StrategyModel
	err := suite.db.Where("user_id = ?", "user-1").Find(&strategies).Error
	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), len(strategies), 3)
}

// TestConcurrentAccess 测试并发访问
func (suite *DatabaseTestSuite) TestConcurrentAccess() {
	const goroutines = 10
	done := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			task := &storage.TaskModel{
				ID:          fmt.Sprintf("concurrent-task-%d", id),
				UserID:      "user-1",
				Name:        "concurrent-task",
				StrategyIDs: `["strategy-1"]`,
				OutputType:  "pcap",
				Status:      "pending",
			}
			err := suite.db.Create(task).Error
			done <- err
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		select {
		case err := <-done:
			assert.NoError(suite.T(), err)
		case <-time.After(5 * time.Second):
			suite.T().Fatal("Timeout waiting for goroutine")
		}
	}

	var tasks []storage.TaskModel
	err := suite.db.Where("user_id = ?", "user-1").Find(&tasks).Error
	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), len(tasks), goroutines)
}

// TestDatabaseIntegration 运行数据库集成测试套件
func TestDatabaseIntegration(t *testing.T) {
	suite.Run(t, new(DatabaseTestSuite))
}
