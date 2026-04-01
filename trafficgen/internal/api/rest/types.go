// Package rest provides REST API handlers.
package rest

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// CreateTaskRequest represents a task creation request.
type CreateTaskRequest struct {
	Name        string         `json:"name" binding:"required"`
	Description string         `json:"description"`
	Protocol    string         `json:"protocol" binding:"required,oneof=tcp udp http dns icmp arp"`
	Spec        core.FlowSpec  `json:"spec" binding:"required"`
	Interface   string         `json:"interface"`
	OutputMode  string         `json:"output_mode"` // interface, pcap, both
	PcapFile    string         `json:"pcap_file,omitempty"`
}

// CreateTaskResponse represents a task creation response.
type CreateTaskResponse struct {
	TaskID  string `json:"task_id"`
	Message string `json:"message"`
}

// TaskResponse represents a task in API responses.
type TaskResponse struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Protocol    string             `json:"protocol"`
	Status      string             `json:"status"`
	Progress    float64            `json:"progress"`
	Stats       core.TaskStats     `json:"stats"`
	CreatedAt   int64              `json:"created_at"`
	StartedAt   int64              `json:"started_at,omitempty"`
	CompletedAt int64              `json:"completed_at,omitempty"`
	Error       string             `json:"error,omitempty"`
}

// ListTasksRequest represents a task list request.
type ListTasksRequest struct {
	Page     int    `form:"page" binding:"min=1"`
	Size     int    `form:"size" binding:"min=1,max=100"`
	Status   string `form:"status"`
	Protocol string `form:"protocol"`
	Sort     string `form:"sort"`
	Order    string `form:"order"`
}

// ListTasksResponse represents a task list response.
type ListTasksResponse struct {
	Tasks []TaskResponse `json:"tasks"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Size  int            `json:"size"`
}

// CreateStrategyRequest represents a strategy creation request.
type CreateStrategyRequest struct {
	Name     string                 `json:"name" binding:"required"`
	Protocol string                 `json:"protocol" binding:"required"`
	Config   map[string]interface{} `json:"config"`
}

// StrategyResponse represents a strategy in API responses.
type StrategyResponse struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Protocol  string                 `json:"protocol"`
	Config    map[string]interface{} `json:"config"`
	CreatedAt int64                  `json:"created_at"`
	UpdatedAt int64                  `json:"updated_at"`
}

// SystemStatusResponse represents system status.
type SystemStatusResponse struct {
	Running      bool              `json:"running"`
	CPUUsage     float64           `json:"cpu_usage"`
	MemoryMB     float64           `json:"memory_mb"`
	ActiveTasks  int               `json:"active_tasks"`
	BufferStatus map[string]interface{} `json:"buffer_status"`
	Uptime       int64             `json:"uptime"`
}

// InterfaceResponse represents a network interface.
type InterfaceResponse struct {
	Name        string `json:"name"`
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	IsUp        bool   `json:"is_up"`
	LinkUp      bool   `json:"link_up"`
	MTU         int    `json:"mtu"`
	Description string `json:"description"`
}

// PortStatusResponse represents port allocation status.
type PortStatusResponse struct {
	Interface  string `json:"interface"`
	Port       uint16 `json:"port"`
	Allocated  bool   `json:"allocated"`
	TaskID     string `json:"task_id,omitempty"`
	AllocatedAt int64 `json:"allocated_at,omitempty"`
}

// LoginRequest represents a login request.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents a login response.
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// SettingsResponse represents system settings.
type SettingsResponse struct {
	MaxTasks    int    `json:"max_tasks"`
	BufferSize  int    `json:"buffer_size"`
	LogLevel    string `json:"log_level"`
}

// UpdateSettingsRequest represents a settings update request.
type UpdateSettingsRequest struct {
	MaxTasks   *int    `json:"max_tasks,omitempty"`
	BufferSize *int    `json:"buffer_size,omitempty"`
	LogLevel   *string `json:"log_level,omitempty"`
}

// PaginationParams represents standard pagination parameters.
type PaginationParams struct {
	Page  int `form:"page" binding:"min=1"`
	Size  int `form:"size" binding:"min=1,max=100"`
}

// PaginationMeta represents pagination metadata.
type PaginationMeta struct {
	Total    int `json:"total"`
	Page     int `json:"page"`
	Size     int `json:"size"`
	Pages    int `json:"pages"`
}
