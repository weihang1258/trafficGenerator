package rest

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

// SystemStatusResponse represents system status.
type SystemStatusResponse struct {
	Running      bool                   `json:"running"`
	ActiveTasks  int                    `json:"active_tasks"`
	BufferStatus map[string]interface{} `json:"buffer_status"`
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
