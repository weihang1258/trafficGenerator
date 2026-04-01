// Package storage provides database access.
package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
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
		db, err = gorm.Open(sqlite.Open(cfg.SQLite.Path), gormConfig)
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

	return &DB{
		DB:     db,
		config: cfg,
	}, nil
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

	offset := (page - 1) * size
	if err := query.Order("created_at DESC").Offset(offset).Limit(size).Find(&tasks).Error; err != nil {
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

	offset := (page - 1) * size
	if err := r.db.Order("created_at DESC").Offset(offset).Limit(size).Find(&strategies).Error; err != nil {
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

	offset := (page - 1) * size
	if err := query.Order("created_at DESC").Offset(offset).Limit(size).Find(&histories).Error; err != nil {
		return nil, 0, err
	}

	return histories, total, nil
}
