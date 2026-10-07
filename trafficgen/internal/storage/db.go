// Package storage provides database access.
package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sqlite "github.com/glebarez/sqlite" // pure Go SQLite driver
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/trafficgen/trafficgen/pkg/config"
)

// DB wraps the gorm.DB with additional functionality.
type DB struct {
	*gorm.DB
	config *config.DatabaseConfig
}

// NewDB creates a new database connection.
func NewDB(cfg *config.DatabaseConfig) (*DB, error) {
	return NewDBWithAdmin(cfg, nil)
}

// sqliteDSN 把配置的 SQLite 路径补上 WAL/busy_timeout pragma（v1 发布项）。
// MCP 客户端高频轮询（读）与任务状态写并发：默认 DELETE 日志模式写阻塞读、
// 锁放大，journal_mode=WAL 读写不互斥；busy_timeout 让锁竞争等待 10s 而非
// 立即 SQLITE_BUSY。pragma 经 DSN 传给驱动——连接池每条新连接都继承
// （打开后补执行 PRAGMA 只影响单连接）。路径自带查询串（用户自管 DSN）
// 时用 & 续接，不重复加 ?。
func sqliteDSN(path string) string {
	// _txlock=immediate：gorm 显式事务默认 BEGIN DEFERRED，"先读后写"在并发
	// 下的锁升级失败会**立即**返回 SQLITE_BUSY、不受 busy_timeout 保护
	//（NEW-P2-20：8 路并发批次 3 失败）。IMMEDIATE 让事务一开就拿写锁、
	// 排队全程受 busy_timeout 保护。库内事务均为写事务，只读事务无此路径。
	// busy_timeout 60s（原 10s，2026-10-07 全量套件实测定标）：pcap_packets
	// 行级持久化使 4 路并行套件的 500 行/批插入把 WAL 写锁队列压满，10s
	// 等待在尖峰随机过期（modbus/tftp 大套件 13 例随机 BUSY，两次重跑
	// 失败集不同=非确定性竞争）。60s 让创建请求排队越过 pcap 批插尖峰。
	const pragma = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(60000)&_txlock=immediate"
	if strings.Contains(path, "?") {
		return path + "&" + pragma
	}
	return path + "?" + pragma
}

// NewDBWithAdmin creates a new database connection and initializes admin account.
func NewDBWithAdmin(cfg *config.DatabaseConfig, adminCfg *config.AdminConfig) (*DB, error) {
	var db *gorm.DB
	var err error

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	switch cfg.Type {
	case "postgres":
		dsn := cfg.GetDSN()
		db, err = gorm.Open(postgres.Open(dsn), gormConfig)
	case "sqlite":
		// 首次启动（systemd 新装、解包直跑）时 data/ 子目录尚不存在：
		// SQLITE_CANTOPEN 会被 gorm 误报为 "out of memory (14)"。
		// 打开前自建父目录，发布包默认配置才能开箱即用。
		if dir := filepath.Dir(cfg.SQLite.Path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("create sqlite dir %s: %w", dir, err)
			}
		}
		db, err = gorm.Open(sqlite.Open(sqliteDSN(cfg.SQLite.Path)), gormConfig)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.Pool.MaxOpen)
	sqlDB.SetMaxIdleConns(cfg.Pool.MaxIdle)
	sqlDB.SetConnMaxLifetime(cfg.Pool.ConnLifetime)

	// Auto migrate
	if err := AutoMigrate(db); err != nil {
		return nil, fmt.Errorf("failed to auto migrate: %w", err)
	}

	database := &DB{
		DB:     db,
		config: cfg,
	}

	// Initialize admin account if provided
	if adminCfg != nil {
		if err := database.initAdminUser(adminCfg); err != nil {
			return nil, fmt.Errorf("failed to initialize admin user: %w", err)
		}
	}

	return database, nil
}

// initAdminUser initializes the default admin user.
func (db *DB) initAdminUser(adminCfg *config.AdminConfig) error {
	// Check if admin user already exists
	var count int64
	if err := db.Model(&UserModel{}).Where("username = ?", adminCfg.Username).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check admin user: %w", err)
	}

	if count > 0 {
		// Admin user already exists, update password if needed
		var admin UserModel
		if err := db.Where("username = ?", adminCfg.Username).First(&admin).Error; err != nil {
			return fmt.Errorf("failed to get admin user: %w", err)
		}

		// Update password if it doesn't match
		if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(adminCfg.Password)); err != nil {
			// Password doesn't match, update it
			passwordHash, err := bcrypt.GenerateFromPassword([]byte(adminCfg.Password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("failed to hash password: %w", err)
			}
			admin.PasswordHash = string(passwordHash)
			if err := db.Save(&admin).Error; err != nil {
				return fmt.Errorf("failed to update admin password: %w", err)
			}
		}
		return nil
	}

	// Create admin user
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(adminCfg.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	admin := &UserModel{
		ID:           uuid.New().String(),
		Username:     adminCfg.Username,
		PasswordHash: string(passwordHash),
		Email:        adminCfg.Email,
		Role:         "admin",
		Enabled:      true,
	}

	if err := db.Create(admin).Error; err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	return nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping checks the database connection.
func (db *DB) Ping(ctx context.Context) error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// IsConnected returns true if the database is connected.
func (db *DB) IsConnected() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	return db.Ping(ctx) == nil
}

// GetSettings returns the singleton settings row. If it does not exist yet,
// it seeds a row with the documented defaults and returns it.
func (db *DB) GetSettings() (*SettingsModel, error) {
	var s SettingsModel
	err := db.First(&s, "id = ?", "default").Error
	if err == gorm.ErrRecordNotFound {
		seeded := SettingsModel{ID: "default", MaxTasks: 100, BufferSize: 4096, LogLevel: "info"}
		if e := db.Create(&seeded).Error; e != nil {
			return nil, e
		}
		return &seeded, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// SaveSettings upserts the singleton settings row (forces id="default").
func (db *DB) SaveSettings(s *SettingsModel) error {
	s.ID = "default"
	return db.Save(s).Error
}

// CountActiveTasks returns the count of tasks with running or pending status.
func (db *DB) CountActiveTasks() (int64, error) {
	var count int64
	if err := db.Model(&TaskModel{}).Where("status IN ?", []string{"running", "pending"}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// CountTasksByProtocol returns a map of protocol -> task count for all tasks.
func (db *DB) CountTasksByProtocol() (map[string]int64, error) {
	type protocolCount struct {
		Protocol string
		Count    int64
	}
	var results []protocolCount
	if err := db.Model(&TaskModel{}).Select("protocol, count(*) as count").Where("protocol != ''").Group("protocol").Find(&results).Error; err != nil {
		return nil, err
	}
	counts := make(map[string]int64)
	for _, r := range results {
		counts[r.Protocol] = r.Count
	}
	return counts, nil
}

// TaskRepository provides task database operations.
type TaskRepository struct {
	db *DB
}

// NewTaskRepository creates a new task repository.
func NewTaskRepository(db *DB) *TaskRepository {
	return &TaskRepository{db: db}
}

// Create creates a new task.
func (r *TaskRepository) Create(task *TaskModel) error {
	return r.db.Create(task).Error
}

// Get retrieves a task by ID.
func (r *TaskRepository) Get(id string) (*TaskModel, error) {
	var task TaskModel
	if err := r.db.First(&task, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

// Update updates a task.
func (r *TaskRepository) Update(task *TaskModel) error {
	return r.db.Save(task).Error
}

// Delete deletes a task.
func (r *TaskRepository) Delete(id string) error {
	return r.db.Delete(&TaskModel{}, "id = ?", id).Error
}

// List lists tasks with pagination.
func (r *TaskRepository) List(page, size int, status, protocol string) ([]TaskModel, int64, error) {
	var tasks []TaskModel
	var total int64

	query := r.db.Model(&TaskModel{})

	if status != "" {
		query = query.Where("status = ?", status)
	}
	if protocol != "" {
		query = query.Where("protocol = ?", protocol)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// size == 0 = 全量拉取（用户裁定 2026-10-04）。
	if size > 0 {
		if err := query.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&tasks).Error; err != nil {
			return nil, 0, err
		}
	} else if err := query.Order("created_at DESC").Find(&tasks).Error; err != nil {
		return nil, 0, err
	}

	return tasks, total, nil
}

// GetByStatus retrieves tasks by status.
func (r *TaskRepository) GetByStatus(status string) ([]TaskModel, error) {
	var tasks []TaskModel
	if err := r.db.Where("status = ?", status).Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

// StrategyRepository provides strategy database operations.
type StrategyRepository struct {
	db *DB
}

// NewStrategyRepository creates a new strategy repository.
func NewStrategyRepository(db *DB) *StrategyRepository {
	return &StrategyRepository{db: db}
}

// Create creates a new strategy.
func (r *StrategyRepository) Create(strategy *StrategyModel) error {
	return r.db.Create(strategy).Error
}

// Get retrieves a strategy by ID.
func (r *StrategyRepository) Get(id string) (*StrategyModel, error) {
	var strategy StrategyModel
	if err := r.db.First(&strategy, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &strategy, nil
}

// GetByName retrieves a strategy by name.
func (r *StrategyRepository) GetByName(name string) (*StrategyModel, error) {
	var strategy StrategyModel
	if err := r.db.First(&strategy, "name = ?", name).Error; err != nil {
		return nil, err
	}
	return &strategy, nil
}

// Update updates a strategy.
func (r *StrategyRepository) Update(strategy *StrategyModel) error {
	return r.db.Save(strategy).Error
}

// Delete deletes a strategy.
func (r *StrategyRepository) Delete(id string) error {
	return r.db.Delete(&StrategyModel{}, "id = ?", id).Error
}

// List lists strategies with pagination.
func (r *StrategyRepository) List(page, size int) ([]StrategyModel, int64, error) {
	var strategies []StrategyModel
	var total int64

	if err := r.db.Model(&StrategyModel{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// size == 0 = 全量拉取（用户裁定 2026-10-04）。
	if size > 0 {
		if err := r.db.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&strategies).Error; err != nil {
			return nil, 0, err
		}
	} else if err := r.db.Order("created_at DESC").Find(&strategies).Error; err != nil {
		return nil, 0, err
	}

	return strategies, total, nil
}

// HistoryRepository provides history database operations.
type HistoryRepository struct {
	db *DB
}

// NewHistoryRepository creates a new history repository.
func NewHistoryRepository(db *DB) *HistoryRepository {
	return &HistoryRepository{db: db}
}

// Create creates a new history record.
func (r *HistoryRepository) Create(history *HistoryModel) error {
	return r.db.Create(history).Error
}

// List lists history with pagination.
func (r *HistoryRepository) List(page, size int, startTime, endTime time.Time) ([]HistoryModel, int64, error) {
	var histories []HistoryModel
	var total int64

	query := r.db.Model(&HistoryModel{})

	if !startTime.IsZero() {
		query = query.Where("created_at >= ?", startTime)
	}
	if !endTime.IsZero() {
		query = query.Where("created_at <= ?", endTime)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// size == 0 = 全量拉取（用户裁定 2026-10-04）。
	if size > 0 {
		if err := query.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&histories).Error; err != nil {
			return nil, 0, err
		}
	} else if err := query.Order("created_at DESC").Find(&histories).Error; err != nil {
		return nil, 0, err
	}

	return histories, total, nil
}
