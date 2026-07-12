package rest

import (
	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/logger"
)

// SettingsHandler handles settings requests. Settings are persisted to the DB
// (surviving restarts) and applied to the running system where possible.
type SettingsHandler struct {
	db     *storage.DB
	engine *core.Engine
}

// SettingsConfig is the API model for settings.
type SettingsConfig struct {
	MaxTasks   int    `json:"max_tasks"`
	BufferSize int    `json:"buffer_size"`
	LogLevel   string `json:"log_level"`
}

// NewSettingsHandler creates a new settings handler backed by db and engine.
func NewSettingsHandler(db *storage.DB, engine *core.Engine) *SettingsHandler {
	return &SettingsHandler{db: db, engine: engine}
}

// GetConfig returns the current settings (reads from DB). Intended for testing
// and internal use; Get is the HTTP handler.
func (h *SettingsHandler) GetConfig() SettingsConfig {
	if h.db == nil {
		return SettingsConfig{MaxTasks: 100, BufferSize: 4096, LogLevel: "info"}
	}
	s, err := h.db.GetSettings()
	if err != nil {
		return SettingsConfig{MaxTasks: 100, BufferSize: 4096, LogLevel: "info"}
	}
	return SettingsConfig{MaxTasks: s.MaxTasks, BufferSize: s.BufferSize, LogLevel: s.LogLevel}
}

// Get returns current settings.
// GET /api/v1/settings
func (h *SettingsHandler) Get(c *gin.Context) {
	Success(c, h.GetConfig())
}

// Update updates settings: persists to DB and applies runtime-applicable items
// (log_level and max_tasks take effect immediately; buffer_size applies on next
// engine restart since the ring buffer is fixed-size).
// PUT /api/v1/settings
func (h *SettingsHandler) Update(c *gin.Context) {
	var req SettingsConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Validate log_level before persisting (avoid saving an invalid value).
	if req.LogLevel != "" {
		if err := logger.SetLevel(req.LogLevel); err != nil {
			BadRequest(c, "invalid log_level: "+err.Error())
			return
		}
	}

	// Load current row (seeds defaults if missing), apply changes, persist.
	s, err := h.db.GetSettings()
	if err != nil {
		InternalError(c, "failed to load settings: "+err.Error())
		return
	}
	if req.MaxTasks > 0 {
		s.MaxTasks = req.MaxTasks
	}
	if req.BufferSize > 0 {
		s.BufferSize = req.BufferSize
	}
	if req.LogLevel != "" {
		s.LogLevel = req.LogLevel
	}
	if err := h.db.SaveSettings(s); err != nil {
		InternalError(c, "failed to save settings: "+err.Error())
		return
	}

	// log_level already applied above; apply max_tasks now.
	if req.MaxTasks > 0 && h.engine != nil {
		h.engine.SetMaxTasks(req.MaxTasks)
	}

	SuccessWithMessage(c, "settings updated", SettingsConfig{
		MaxTasks:   s.MaxTasks,
		BufferSize: s.BufferSize,
		LogLevel:   s.LogLevel,
	})
}
