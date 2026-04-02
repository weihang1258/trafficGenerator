package integration_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
	"gorm.io/gorm"
)

// DatabaseTestSuite 数据库集成测试套件
type DatabaseTestSuite struct {
	suite.Suite
	db *storage.DB
}

// SetupSuite 初始化测试套件
func (suite *DatabaseTestSuite) SetupSuite() {
	cfg := &config.DatabaseConfig{
		Type: "sqlite",
		DSN:  ":memory:",
	}

	db, err := storage.NewDB(cfg)
	assert.NoError(suite.T(), err)
	suite.db = db
}

// TearDownSuite 清理测试套件
func (suite *DatabaseTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
}

// TestCreateTask 测试创建任务
func (suite *DatabaseTestSuite) TestCreateTask() {
	task := &storage.Task{
		Name:     "test-task",
		Protocol: "tcp",
		Status:   "pending",
		Config:   `{"src_ip":"192.168.1.1","dst_ip":"192.168.1.2"}`,
	}

	err := suite.db.CreateTask(task)
	assert.NoError(suite.T(), err)
	assert.NotZero(suite.T(), task.ID)
}

// TestGetTask 测试获取任务
func (suite *DatabaseTestSuite) TestGetTask() {
	// 创建任务
	task := &storage.Task{
		Name:     "test-task-get",
		Protocol: "udp",
		Status:   "pending",
		Config:   `{"src_ip":"192.168.1.1"}`,
	}
	err := suite.db.CreateTask(task)
	assert.NoError(suite.T(), err)

	// 获取任务
	retrievedTask, err := suite.db.GetTask(task.ID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), task.Name, retrievedTask.Name)
	assert.Equal(suite.T(), task.Protocol, retrievedTask.Protocol)
}

// TestUpdateTask 测试更新任务
func (suite *DatabaseTestSuite) TestUpdateTask() {
	// 创建任务
	task := &storage.Task{
		Name:     "test-task-update",
		Protocol: "tcp",
		Status:   "pending",
		Config:   `{}`,
	}
	err := suite.db.CreateTask(task)
	assert.NoError(suite.T(), err)

	// 更新任务
	task.Status = "running"
	err = suite.db.UpdateTask(task)
	assert.NoError(suite.T(), err)

	// 验证更新
	retrievedTask, err := suite.db.GetTask(task.ID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "running", retrievedTask.Status)
}

// TestDeleteTask 测试删除任务
func (suite *DatabaseTestSuite) TestDeleteTask() {
	// 创建任务
	task := &storage.Task{
		Name:     "test-task-delete",
		Protocol: "tcp",
		Status:   "pending",
		Config:   `{}`,
	}
	err := suite.db.CreateTask(task)
	assert.NoError(suite.T(), err)

	// 删除任务
	err = suite.db.DeleteTask(task.ID)
	assert.NoError(suite.T(), err)

	// 验证删除
	_, err = suite.db.GetTask(task.ID)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), gorm.ErrRecordNotFound, err)
}

// TestListTasks 测试列出任务
func (suite *DatabaseTestSuite) TestListTasks() {
	// 创建多个任务
	for i := 0; i < 5; i++ {
		task := &storage.Task{
			Name:     "test-task-list-" + string(rune(i)),
			Protocol: "tcp",
			Status:   "pending",
			Config:   `{}`,
		}
		err := suite.db.CreateTask(task)
		assert.NoError(suite.T(), err)
	}

	// 列出任务
	tasks, total, err := suite.db.ListTasks(1, 10, "", "")
	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), total, 5)
	assert.GreaterOrEqual(suite.T(), len(tasks), 5)
}

// TestListTasksWithFilter 测试带过滤条件的任务列表
func (suite *DatabaseTestSuite) TestListTasksWithFilter() {
	// 创建不同状态的任务
	task1 := &storage.Task{
		Name:     "task-running",
		Protocol: "tcp",
		Status:   "running",
		Config:   `{}`,
	}
	task2 := &storage.Task{
		Name:     "task-pending",
		Protocol: "udp",
		Status:   "pending",
		Config:   `{}`,
	}
	suite.db.CreateTask(task1)
	suite.db.CreateTask(task2)

	// 按状态过滤
	tasks, total, err := suite.db.ListTasks(1, 10, "running", "")
	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), total, 1)
	for _, task := range tasks {
		assert.Equal(suite.T(), "running", task.Status)
	}

	// 按协议过滤
	tasks, total, err = suite.db.ListTasks(1, 10, "", "udp")
	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), total, 1)
	for _, task := range tasks {
		assert.Equal(suite.T(), "udp", task.Protocol)
	}
}

// TestCreateStrategy 测试创建策略
func (suite *DatabaseTestSuite) TestCreateStrategy() {
	strategy := &storage.Strategy{
		Name:        "test-strategy",
		Description: "Test strategy",
		Config:      `{"protocol":"tcp"}`,
	}

	err := suite.db.CreateStrategy(strategy)
	assert.NoError(suite.T(), err)
	assert.NotZero(suite.T(), strategy.ID)
}

// TestGetStrategy 测试获取策略
func (suite *DatabaseTestSuite) TestGetStrategy() {
	strategy := &storage.Strategy{
		Name:        "test-strategy-get",
		Description: "Test",
		Config:      `{}`,
	}
	err := suite.db.CreateStrategy(strategy)
	assert.NoError(suite.T(), err)

	retrievedStrategy, err := suite.db.GetStrategy(strategy.ID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), strategy.Name, retrievedStrategy.Name)
}

// TestUpdateStrategy 测试更新策略
func (suite *DatabaseTestSuite) TestUpdateStrategy() {
	strategy := &storage.Strategy{
		Name:        "test-strategy-update",
		Description: "Before update",
		Config:      `{}`,
	}
	err := suite.db.CreateStrategy(strategy)
	assert.NoError(suite.T(), err)

	strategy.Description = "After update"
	err = suite.db.UpdateStrategy(strategy)
	assert.NoError(suite.T(), err)

	retrievedStrategy, err := suite.db.GetStrategy(strategy.ID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "After update", retrievedStrategy.Description)
}

// TestDeleteStrategy 测试删除策略
func (suite *DatabaseTestSuite) TestDeleteStrategy() {
	strategy := &storage.Strategy{
		Name:        "test-strategy-delete",
		Description: "Test",
		Config:      `{}`,
	}
	err := suite.db.CreateStrategy(strategy)
	assert.NoError(suite.T(), err)

	err = suite.db.DeleteStrategy(strategy.ID)
	assert.NoError(suite.T(), err)

	_, err = suite.db.GetStrategy(strategy.ID)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), gorm.ErrRecordNotFound, err)
}

// TestListStrategies 测试列出策略
func (suite *DatabaseTestSuite) TestListStrategies() {
	for i := 0; i < 3; i++ {
		strategy := &storage.Strategy{
			Name:        "test-strategy-list",
			Description: "Test",
			Config:      `{}`,
		}
		err := suite.db.CreateStrategy(strategy)
		assert.NoError(suite.T(), err)
	}

	strategies, err := suite.db.ListStrategies()
	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), len(strategies), 3)
}

// TestConcurrentAccess 测试并发访问
func (suite *DatabaseTestSuite) TestConcurrentAccess() {
	const goroutines = 10
	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			task := &storage.Task{
				Name:     "concurrent-task",
				Protocol: "tcp",
				Status:   "pending",
				Config:   `{}`,
			}
			err := suite.db.CreateTask(task)
			assert.NoError(suite.T(), err)
			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			suite.T().Fatal("Timeout waiting for goroutine")
		}
	}

	tasks, total, err := suite.db.ListTasks(1, 100, "", "")
	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), total, goroutines)
	assert.GreaterOrEqual(suite.T(), len(tasks), goroutines)
}

// TestDatabaseIntegration 运行数据库集成测试套件
func TestDatabaseIntegration(t *testing.T) {
	suite.Run(t, new(DatabaseTestSuite))
}
