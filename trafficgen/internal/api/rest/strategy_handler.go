package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"gorm.io/gorm"
)

// StrategyHandler handles strategy requests.
type StrategyHandler struct {
	db *storage.DB
}

// NewStrategyHandler creates a new strategy handler.
func NewStrategyHandler(db *storage.DB) *StrategyHandler {
	return &StrategyHandler{db: db}
}

// CreateStrategyRequest represents a create strategy request.
type CreateStrategyRequest struct {
	Name        string                 `json:"name" binding:"required"`
	Protocol    string                 `json:"protocol" binding:"required"`
	Config      map[string]interface{} `json:"config" binding:"required"`
	FlowControl *FlowControlRequest    `json:"flow_control"`
}

// FlowControlRequest represents flow control configuration.
type FlowControlRequest struct {
	Type  string  `json:"type" binding:"required"`  // "flows", "cps", "bps", "ratio", "time"
	Value float64 `json:"value" binding:"required"` // 流数/速率/比例/时间
}

// StrategyResponse represents a strategy response.
type StrategyResponse struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	Name        string                 `json:"name"`
	Protocol    string                 `json:"protocol"`
	Config      map[string]interface{} `json:"config"`
	FlowControl *FlowControlRequest    `json:"flow_control"`
	TaskCount   int                    `json:"task_count"`
	CreatedAt   int64                  `json:"created_at"`
	UpdatedAt   int64                  `json:"updated_at"`
}

// TaskBrief represents a brief task reference.
type TaskBrief struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Create creates a new strategy (idempotent).
func (h *StrategyHandler) Create(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var req CreateStrategyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Validate network config fields
	if errMsg := validateConfigNetwork(req.Config); errMsg != "" {
		BadRequest(c, errMsg)
		return
	}
	// Validate DSCP/ECN/VLAN ranges on the raw config before mapToFlowSpec
	// truncates them to uint8/uint16 (otherwise dscp=256 silently wraps to 0).
	if err := core.ValidateConfigRanges(req.Config); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Validate protocol
	validProtocols := map[string]bool{"tcp": true, "udp": true, "http": true, "arp": true, "icmp": true, "dns": true}
	if req.Protocol == "" || !validProtocols[req.Protocol] {
		BadRequest(c, "invalid or missing protocol: " + req.Protocol)
		return
	}
	// Validate per-protocol sub-config fields (tcp.mss, icmp.type, etc.)
	// that also truncate silently through uint16/uint8. Runs after protocol
	// validation so req.Protocol is known-good.
	if err := core.ValidateProtocolSubConfigs(req.Config, req.Protocol); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Set default flow control if not provided
	if req.FlowControl == nil {
		req.FlowControl = &FlowControlRequest{
			Type:  "flows",
			Value: 1,
		}
	}


		// Validate flow_control type
		validFlowTypes := map[string]bool{"flows": true, "cps": true, "bps": true, "ratio": true, "time": true}
		if !validFlowTypes[req.FlowControl.Type] {
			BadRequest(c, "invalid flow_control type: must be flows, cps, bps, ratio, or time")
			return
		}

		// Validate flow_control value is positive
		if req.FlowControl.Value <= 0 {
			BadRequest(c, "flow_control value must be positive")
			return
		}
	// Serialize config and flow control
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		BadRequest(c, "invalid config format")
		return
	}

	flowControlJSON, err := json.Marshal(req.FlowControl)
	if err != nil {
		BadRequest(c, "invalid flow_control format")
		return
	}

	// Calculate config hash for idempotent creation
	configHash := calculateConfigHash(req.Protocol, string(configJSON), string(flowControlJSON))

	// Check if strategy already exists for this user
	var existingStrategy storage.StrategyModel
	if err := h.db.Where("user_id = ? AND config_hash = ?", userID, configHash).First(&existingStrategy).Error; err == nil {
		// Strategy exists, return existing ID
		Success(c, map[string]string{
			"id":      existingStrategy.ID,
			"message": "strategy already exists",
		})
		return
	}

	// Create new strategy
	strategy := &storage.StrategyModel{
		ID:          uuid.New().String(),
		UserID:      userID,
		Name:        req.Name,
		Protocol:    req.Protocol,
		Config:      string(configJSON),
		FlowControl: string(flowControlJSON),
		ConfigHash:  configHash,
	}

	if err := h.db.Create(strategy).Error; err != nil {
		InternalError(c, "failed to create strategy: "+err.Error())
		return
	}

	Created(c, map[string]string{"id": strategy.ID})
}

// List lists all strategies for the current user.
func (h *StrategyHandler) List(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var strategies []storage.StrategyModel
	if err := h.db.Where("user_id = ?", userID).Find(&strategies).Error; err != nil {
		InternalError(c, "failed to list strategies: "+err.Error())
		return
	}

	result := make([]StrategyResponse, len(strategies))
	for i, s := range strategies {
		var config map[string]interface{}
		json.Unmarshal([]byte(s.Config), &config)

		var flowControl FlowControlRequest
		json.Unmarshal([]byte(s.FlowControl), &flowControl)

		// Count tasks using this strategy
		var taskCount int64
		h.db.Model(&storage.TaskModel{}).
			Where("user_id = ? AND EXISTS (SELECT 1 FROM json_each(strategy_ids) WHERE json_each.value = ?)", userID, s.ID).
			Count(&taskCount)

		result[i] = StrategyResponse{
			ID:          s.ID,
			UserID:      s.UserID,
			Name:        s.Name,
			Protocol:    s.Protocol,
			Config:      config,
			FlowControl: &flowControl,
			TaskCount:   int(taskCount),
			CreatedAt:   s.CreatedAt.Unix(),
			UpdatedAt:   s.UpdatedAt.Unix(),
		}
	}

	Success(c, result)
}

// Get gets a strategy by ID.
func (h *StrategyHandler) Get(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing strategy id")
		return
	}

	var strategy storage.StrategyModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&strategy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "strategy not found")
			return
		}
		InternalError(c, "failed to get strategy: "+err.Error())
		return
	}

	var config map[string]interface{}
	json.Unmarshal([]byte(strategy.Config), &config)

	var flowControl FlowControlRequest
	json.Unmarshal([]byte(strategy.FlowControl), &flowControl)

	Success(c, StrategyResponse{
		ID:          strategy.ID,
		UserID:      strategy.UserID,
		Name:        strategy.Name,
		Protocol:    strategy.Protocol,
		Config:      config,
		FlowControl: &flowControl,
		CreatedAt:   strategy.CreatedAt.Unix(),
		UpdatedAt:   strategy.UpdatedAt.Unix(),
	})
}

// Update updates a strategy.
func (h *StrategyHandler) Update(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing strategy id")
		return
	}

	var req CreateStrategyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Validate network config fields
	if errMsg := validateConfigNetwork(req.Config); errMsg != "" {
		BadRequest(c, errMsg)
		return
	}
	// Validate DSCP/ECN/VLAN ranges on the raw config before mapToFlowSpec
	// truncates them to uint8/uint16 (otherwise dscp=256 silently wraps to 0).
	if err := core.ValidateConfigRanges(req.Config); err != nil {
		BadRequest(c, err.Error())
		return
	}
	// Validate per-protocol sub-config fields (tcp.mss, icmp.type, etc.)
	// that also truncate silently through uint16/uint8. Unknown/empty protocol
	// is a no-op (switch has no matching case).
	if err := core.ValidateProtocolSubConfigs(req.Config, req.Protocol); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Check if strategy exists and belongs to user
	var strategy storage.StrategyModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&strategy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "strategy not found")
			return
		}
		InternalError(c, "failed to get strategy: "+err.Error())
		return
	}


	// Validate flow_control type and value if provided
	if req.FlowControl != nil {
		validFlowTypes := map[string]bool{"flows": true, "cps": true, "bps": true, "ratio": true, "time": true}
		if !validFlowTypes[req.FlowControl.Type] {
			BadRequest(c, "invalid flow_control type: must be flows, cps, bps, ratio, or time")
			return
		}
		if req.FlowControl.Value <= 0 {
			BadRequest(c, "flow_control value must be positive")
			return
		}
	}
	// Serialize config and flow control
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		BadRequest(c, "invalid config format")
		return
	}

	flowControlJSON, err := json.Marshal(req.FlowControl)
	if err != nil {
		BadRequest(c, "invalid flow_control format")
		return
	}

	// Calculate new config hash
	configHash := calculateConfigHash(req.Protocol, string(configJSON), string(flowControlJSON))

	// Update strategy
	strategy.Name = req.Name
	strategy.Protocol = req.Protocol
	strategy.Config = string(configJSON)
	strategy.FlowControl = string(flowControlJSON)
	strategy.ConfigHash = configHash

	if err := h.db.Save(&strategy).Error; err != nil {
		InternalError(c, "failed to update strategy: "+err.Error())
		return
	}

	SuccessWithMessage(c, "strategy updated", nil)
}

// Delete deletes a strategy.
func (h *StrategyHandler) Delete(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing strategy id")
		return
	}

	// Check if strategy exists and belongs to user
	var strategy storage.StrategyModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&strategy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "strategy not found")
			return
		}
		InternalError(c, "failed to get strategy: "+err.Error())
		return
	}

	// Check if strategy is used by any tasks (JSON array exact match)
	var taskCount int64
	h.db.Model(&storage.TaskModel{}).
		Where("user_id = ? AND EXISTS (SELECT 1 FROM json_each(strategy_ids) WHERE json_each.value = ?)", userID, id).
		Count(&taskCount)
	if taskCount > 0 {
		BadRequest(c, "strategy is used by tasks, cannot delete")
		return
	}

	// Delete strategy
	if err := h.db.Delete(&strategy).Error; err != nil {
		InternalError(c, "failed to delete strategy: "+err.Error())
		return
	}

	SuccessWithMessage(c, "strategy deleted", nil)
}

// calculateConfigHash calculates a hash for strategy configuration.
func calculateConfigHash(protocol, config, flowControl string) string {
	data := protocol + config + flowControl
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// validateIP checks that a string is a valid IPv4 address.
func validateIP(ip string) bool {
	return net.ParseIP(ip) != nil && regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`).MatchString(ip)
}

// validateMAC checks that a string is a valid MAC address (XX:XX:XX:XX:XX:XX).
func validateMAC(mac string) bool {
	return regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`).MatchString(mac)
}

// validateConfigNetwork validates IP and MAC fields in a config map.
func validateConfigNetwork(config map[string]interface{}) string {
	for _, key := range []string{"src_ip", "dst_ip"} {
		val, ok := config[key]
		if ok {
			s, ok := val.(string)
			if ok && s != "" && !validateIP(s) {
				return "invalid IP format: " + key + " = " + s
			}
		}
	}
	for _, key := range []string{"src_mac", "dst_mac"} {
		val, ok := config[key]
		if ok {
			s, ok := val.(string)
			if ok && s != "" && !validateMAC(s) {
				return "invalid MAC format: " + key + " = " + s
			}
		}
	}
	return ""
}

// ListTasks returns tasks that use a given strategy.
func (h *StrategyHandler) ListTasks(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing strategy id")
		return
	}

	// Verify strategy exists and belongs to user
	var strategy storage.StrategyModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&strategy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "strategy not found")
			return
		}
		InternalError(c, "failed to get strategy: "+err.Error())
		return
	}

	// Find tasks referencing this strategy
	var tasks []storage.TaskModel
	h.db.Where("user_id = ? AND EXISTS (SELECT 1 FROM json_each(strategy_ids) WHERE json_each.value = ?)", userID, id).
		Select("id, name, status").
		Find(&tasks)

	result := make([]TaskBrief, len(tasks))
	for i, t := range tasks {
		result[i] = TaskBrief{
			ID:     t.ID,
			Name:   t.Name,
			Status: t.Status,
		}
	}

	Success(c, result)
}
