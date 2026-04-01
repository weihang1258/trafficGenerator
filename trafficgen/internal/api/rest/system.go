package rest

import (
	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
)

// SystemHandler handles system-related requests.
type SystemHandler struct {
	engine *core.Engine
}

// NewSystemHandler creates a new system handler.
func NewSystemHandler(engine *core.Engine) *SystemHandler {
	return &SystemHandler{engine: engine}
}

// GetStatus returns the system status.
// GET /api/v1/system/status
func (h *SystemHandler) GetStatus(c *gin.Context) {
	stats := h.engine.GetStats()

	Success(c, SystemStatusResponse{
		Running:      h.engine.IsRunning(),
		ActiveTasks:  0, // TODO: Count active tasks
		BufferStatus: stats["buffer"].(map[string]interface{}),
	})
}

// GetProtocols returns the list of supported protocols.
// GET /api/v1/system/protocols
func (h *SystemHandler) GetProtocols(c *gin.Context) {
	protocols := []string{"tcp", "udp", "http", "dns", "icmp", "arp"}
	Success(c, protocols)
}

// GetStats returns detailed engine statistics.
// GET /api/v1/system/stats
func (h *SystemHandler) GetStats(c *gin.Context) {
	stats := h.engine.GetStats()
	Success(c, stats)
}

// HealthCheck returns the health status.
// GET /health
func (h *SystemHandler) HealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "healthy",
	})
}

// ReadyCheck returns the readiness status.
// GET /ready
func (h *SystemHandler) ReadyCheck(c *gin.Context) {
	if !h.engine.IsRunning() {
		c.JSON(503, gin.H{
			"status": "not ready",
			"reason": "engine not running",
		})
		return
	}

	c.JSON(200, gin.H{
		"status":   "ready",
		"database": "connected", // TODO: Check actual database connection
		"redis":    "connected", // TODO: Check actual Redis connection
	})
}
