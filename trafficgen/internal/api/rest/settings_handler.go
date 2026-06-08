package rest

import (
	"sync"

	"github.com/gin-gonic/gin"
)

// SettingsHandler handles settings requests.
type SettingsHandler struct {
	mu     sync.RWMutex
	config SettingsConfig
}

// SettingsConfig holds the current settings.
type SettingsConfig struct {
	MaxTasks   int    `json:"max_tasks"`
	BufferSize int    `json:"buffer_size"`
	LogLevel   string `json:"log_level"`
}

// NewSettingsHandler creates a new settings handler.
func NewSettingsHandler() *SettingsHandler {
	return &SettingsHandler{
		config: SettingsConfig{
			MaxTasks:   100,
			BufferSize: 4096,
			LogLevel:   "info",
		},
	}
}

// Get returns current settings.
func (h *SettingsHandler) Get(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	Success(c, h.config)
}

// Update updates settings.
func (h *SettingsHandler) Update(c *gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var req SettingsConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	if req.MaxTasks > 0 {
		h.config.MaxTasks = req.MaxTasks
	}
	if req.BufferSize > 0 {
		h.config.BufferSize = req.BufferSize
	}
	if req.LogLevel != "" {
		h.config.LogLevel = req.LogLevel
	}

	SuccessWithMessage(c, "settings updated", nil)
}
