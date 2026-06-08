package rest

// PortAllocationBrief represents a brief port allocation for API responses.
type PortAllocationBrief struct {
	Port        uint16 `json:"port"`
	TaskID      string `json:"task_id"`
	AllocatedAt string `json:"allocated_at"`
}

// InterfaceResponse represents a network interface.
type InterfaceResponse struct {
	Name        string               `json:"name"`
	MAC         string               `json:"mac"`
	IPs         []string             `json:"ips"`
	IsUp        bool                 `json:"is_up"`
	LinkUp      bool                 `json:"link_up"`
	MTU         int                  `json:"mtu"`
	Description string               `json:"description"`
	IsVirtual   bool                 `json:"is_virtual"`
	InUse       bool                 `json:"in_use"`
	Allocations []PortAllocationBrief `json:"allocations,omitempty"`
}

// SystemStatusResponse represents system status.
type SystemStatusResponse struct {
	Running      bool                   `json:"running"`
	ActiveTasks  int                    `json:"active_tasks"`
	BufferStatus map[string]interface{} `json:"buffer_status"`
	CpuUsage     float64                `json:"cpu_usage"`
	MemoryMB     float64                `json:"memory_mb"`
	Uptime       int64                  `json:"uptime"`
}

// SettingsResponse represents application settings.
type SettingsResponse struct {
	MaxTasks   int    `json:"max_tasks"`
	BufferSize int    `json:"buffer_size"`
	LogLevel   string `json:"log_level"`
}

// UpdateSettingsRequest represents a settings update request.
type UpdateSettingsRequest struct {
	MaxTasks   *int    `json:"max_tasks"`
	BufferSize *int    `json:"buffer_size"`
	LogLevel   *string `json:"log_level"`
}
