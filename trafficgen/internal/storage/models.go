// Package storage provides database access.
package storage

import (
	"time"

	"gorm.io/gorm"
)

// TaskModel represents a task in the database.
type TaskModel struct {
	ID          string    `gorm:"primaryKey;size:64"`
	Name        string    `gorm:"size:255;not null"`
	Description string    `gorm:"size:1024"`
	Protocol    string    `gorm:"size:32;not null;index"`
	Spec        string    `gorm:"type:text"` // JSON
	Interface   string    `gorm:"size:64"`
	OutputMode  string    `gorm:"size:32"`
	PcapFile    string    `gorm:"size:512"`
	Status      string    `gorm:"size:32;not null;index"`
	Progress    float64   `gorm:"default:0"`
	Error       string    `gorm:"size:1024"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
	StartedAt   *time.Time
	CompletedAt *time.Time
}

// TableName returns the table name.
func (TaskModel) TableName() string {
	return "tasks"
}

// StrategyModel represents a strategy in the database.
type StrategyModel struct {
	ID        string    `gorm:"primaryKey;size:64"`
	Name      string    `gorm:"size:255;not null;uniqueIndex"`
	Protocol  string    `gorm:"size:32;not null;index"`
	Config    string    `gorm:"type:text"` // JSON
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name.
func (StrategyModel) TableName() string {
	return "strategies"
}

// HistoryModel represents a task history record.
type HistoryModel struct {
	ID           string    `gorm:"primaryKey;size:64"`
	TaskID       string    `gorm:"size:64;not null;index"`
	Name         string    `gorm:"size:255;not null"`
	Protocol     string    `gorm:"size:32;not null"`
	Status       string    `gorm:"size:32;not null"`
	PacketsSent  int64     `gorm:"default:0"`
	BytesSent    int64     `gorm:"default:0"`
	Duration     int       `gorm:"default:0"` // seconds
	Error        string    `gorm:"size:1024"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	CompletedAt  *time.Time
}

// TableName returns the table name.
func (HistoryModel) TableName() string {
	return "history"
}

// UserModel represents a user in the database.
type UserModel struct {
	ID           uint      `gorm:"primaryKey;autoIncrement"`
	Username     string    `gorm:"size:64;not null;uniqueIndex"`
	PasswordHash string    `gorm:"size:256;not null"`
	Email        string    `gorm:"size:128;uniqueIndex"`
	Role         string    `gorm:"size:32;not null;default:'user'"`
	Enabled      bool      `gorm:"default:true"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
	LastLoginAt  *time.Time
}

// TableName returns the table name.
func (UserModel) TableName() string {
	return "users"
}

// PortAllocationModel represents a port allocation.
type PortAllocationModel struct {
	ID          uint      `gorm:"primaryKey;autoIncrement"`
	Interface   string    `gorm:"size:64;not null;index"`
	Port        uint16    `gorm:"not null;index"`
	TaskID      string    `gorm:"size:64;index"`
	AllocatedAt time.Time `gorm:"autoCreateTime"`
	ExpiresAt   *time.Time
}

// TableName returns the table name.
func (PortAllocationModel) TableName() string {
	return "port_allocations"
}

// AutoMigrate runs auto migration for all models.
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&TaskModel{},
		&StrategyModel{},
		&HistoryModel{},
		&UserModel{},
		&PortAllocationModel{},
	)
}
