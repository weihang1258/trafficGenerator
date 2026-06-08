// Package storage provides database access.
package storage

import (
	"time"

	"gorm.io/gorm"
)

// TaskModel represents a task in the database.
type TaskModel struct {
	ID           string    `gorm:"primaryKey;size:64"`
	UserID       string    `gorm:"size:64;not null;index"` // 用户ID，数据隔离
	Name         string    `gorm:"size:255;not null"`
	Description  string    `gorm:"size:1024"`
	StrategyIDs  string    `gorm:"type:text"`              // JSON: ["id1", "id2"]
	Protocol     string    `gorm:"size:32"`                // Primary protocol (from first strategy)
	OutputType   string    `gorm:"size:32"`                // "port_group" or "pcap"
	OutputConfig string    `gorm:"type:text"`              // JSON output configuration
	FlowControl  string    `gorm:"type:text"`              // JSON: {"type": "bps", "value": 1000000000}
	Status       string    `gorm:"size:32;not null;index"` // "pending", "running", "stopped", "completed", "error"
	Progress     float64   `gorm:"default:0"`
	ErrorMessage string    `gorm:"size:1024"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
	StartedAt    *time.Time
	CompletedAt  *time.Time
}

// TableName returns the table name.
func (TaskModel) TableName() string {
	return "tasks"
}

// StrategyModel represents a strategy in the database.
type StrategyModel struct {
	ID          string    `gorm:"primaryKey;size:64"`
	UserID      string    `gorm:"size:64;not null;index"` // 用户ID，数据隔离
	Name        string    `gorm:"size:255;not null"`
	Protocol    string    `gorm:"size:32;not null;index"`
	Config      string    `gorm:"type:text"`              // JSON 配置
	FlowControl string    `gorm:"type:text"`              // JSON: {"type": "flows", "value": 1}
	ConfigHash  string    `gorm:"size:64;index"`    // 配置哈希，幂等创建
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
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
	ID           string    `gorm:"primaryKey;size:64"`
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

// PortModel represents a network port.
type PortModel struct {
	ID            string    `gorm:"primaryKey;size:64"`
	Name          string    `gorm:"size:255;not null;uniqueIndex"`
	Type          string    `gorm:"size:20;not null"`  // "libpcap" or "dpdk"
	PCIAddress    string    `gorm:"size:255"`          // PCIe address for DPDK
	Status        string    `gorm:"size:20;not null;default:'idle';index"` // "idle", "using", "maintenance"
	CurrentTaskID string    `gorm:"size:64;index"`
	CreatedAt     time.Time `gorm:"autoCreateTime"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name.
func (PortModel) TableName() string {
	return "ports"
}

// PortGroupModel represents a port group.
type PortGroupModel struct {
	ID          string    `gorm:"primaryKey;size:64"`
	Name        string    `gorm:"size:255;not null;uniqueIndex"`
	PortsConfig string    `gorm:"type:text"` // JSON: [{"interface": "eth0", "weight": 1}]
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name.
func (PortGroupModel) TableName() string {
	return "port_groups"
}

// TokenModel represents a JWT token for validation.
type TokenModel struct {
	ID        string    `gorm:"primaryKey;size:64"`
	UserID    string    `gorm:"size:64;not null;index"`
	TokenHash string    `gorm:"size:255;not null;uniqueIndex"`
	ExpiresAt time.Time `gorm:"not null;index"`
	Status    string    `gorm:"size:20;not null;default:'active'"` // "active", "revoked"
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

// TableName returns the table name.
func (TokenModel) TableName() string {
	return "tokens"
}

// AutoMigrate runs auto migration for all models.
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&TaskModel{},
		&StrategyModel{},
		&HistoryModel{},
		&UserModel{},
		&PortAllocationModel{},
		&PortModel{},
		&PortGroupModel{},
		&TokenModel{},
	)
}
