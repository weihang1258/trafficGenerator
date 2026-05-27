package rest

import (
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
)

// startTime records when the server process started.
var startTime = time.Now()

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

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	Success(c, SystemStatusResponse{
		Running:      h.engine.IsRunning(),
		ActiveTasks:  0, // TODO: Count active tasks
		BufferStatus: stats["buffer"].(map[string]interface{}),
		CpuUsage:     0, // TODO: implement CPU usage calculation
		MemoryMB:     float64(m.Alloc) / 1024 / 1024,
		Uptime:       int64(time.Since(startTime).Seconds()),
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
	engineStats := h.engine.GetStats()

	// 聚合所有任务统计
	var totalPackets, totalBytes int64
	var currentPPS, currentBPS float64
	protocolCount := make(map[string]int64)

	if tasks, ok := engineStats["tasks"].(map[string]interface{}); ok {
		for _, taskData := range tasks {
			if task, ok := taskData.(map[string]interface{}); ok {
				if stats, ok := task["stats"].(map[string]interface{}); ok {
					if packets, ok := stats["packets_sent"].(int64); ok {
						totalPackets += packets
					}
					if bytes, ok := stats["bytes_sent"].(int64); ok {
						totalBytes += bytes
					}
					if pps, ok := stats["current_pps"].(float64); ok {
						currentPPS += pps
					}
					if bps, ok := stats["current_bps"].(float64); ok {
						currentBPS += bps
					}
				}
				if protocol, ok := task["protocol"].(string); ok {
					protocolCount[protocol]++
				}
			}
		}
	}

	response := map[string]interface{}{
		"packets_sent": totalPackets,
		"bytes_sent":   totalBytes,
		"current_pps":  currentPPS,
		"current_bps":  currentBPS,
		"protocols":    protocolCount,
		"buffer":       engineStats["buffer"],
	}

	Success(c, response)
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
