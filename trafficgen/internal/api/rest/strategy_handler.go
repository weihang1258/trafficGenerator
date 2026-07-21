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
	Mode        string                 `json:"mode"`     // "synth" (default) | "replay"
	Protocol    string                 `json:"protocol"` // required for synth; ignored for replay
	Config      map[string]interface{} `json:"config" binding:"required"`
	FlowControl *FlowControlRequest    `json:"flow_control"`
}

// FlowControlRequest represents flow control configuration.
type FlowControlRequest struct {
	Type  string  `json:"type" binding:"required"`  // "flows", "bps", "time" (cps/ratio dropped)
	Value float64 `json:"value" binding:"required"` // 流数/速率/时间
}

// StrategyResponse represents a strategy response.
type StrategyResponse struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	Name        string                 `json:"name"`
	Mode        string                 `json:"mode"`
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

	// Determine mode: default to synth
	mode := req.Mode
	if mode == "" {
		mode = "synth"
	}

	// Set default flow control for synth only (replay leaves nil unless caller
	// explicitly sets one - and only time is accepted then).
	if req.FlowControl == nil && mode != "replay" {
		req.FlowControl = &FlowControlRequest{
			Type:  "flows",
			Value: 1,
		}
	}

	if mode == "replay" {
		h.createReplayStrategy(c, userID, &req)
		return
	}
	h.createSynthStrategy(c, userID, mode, &req)
}

// createReplayStrategy validates + persists a replay-mode strategy. Skips all
// synth-specific validation (network/ranges/protocol/sub-configs); the config
// is validated as a ReplaySpec instead. Strategy-level flow_control only
// accepts "time" (flows is unsupported, bps folds into speed.mode).
func (h *StrategyHandler) createReplayStrategy(c *gin.Context, userID string, req *CreateStrategyRequest) {
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		BadRequest(c, "invalid config format")
		return
	}
	if err := core.ValidateReplaySpec(json.RawMessage(configJSON)); err != nil {
		BadRequest(c, err.Error())
		return
	}
	if req.FlowControl != nil {
		if req.FlowControl.Type != "time" {
			BadRequest(c, "replay strategy flow_control only supports type=time")
			return
		}
		if req.FlowControl.Value <= 0 {
			BadRequest(c, "flow_control value must be positive")
			return
		}
	}
	var flowControlJSON []byte
	if req.FlowControl != nil {
		flowControlJSON, err = json.Marshal(req.FlowControl)
		if err != nil {
			BadRequest(c, "invalid flow_control format")
			return
		}
	}
	configHash := calculateConfigHash("replay", "", string(configJSON), string(flowControlJSON))

	var existing storage.StrategyModel
	if err := h.db.Where("user_id = ? AND config_hash = ?", userID, configHash).First(&existing).Error; err == nil {
		Success(c, map[string]string{"id": existing.ID, "message": "strategy already exists"})
		return
	}
	strategy := &storage.StrategyModel{
		ID:          uuid.New().String(),
		UserID:      userID,
		Name:        req.Name,
		Mode:        "replay",
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

// createSynthStrategy validates + persists a synth-mode strategy (the original
// path). cps/ratio flow-control types are rejected; only flows/bps/time are
// accepted.
func (h *StrategyHandler) createSynthStrategy(c *gin.Context, userID, mode string, req *CreateStrategyRequest) {
	if errMsg := validateConfigNetwork(req.Config); errMsg != "" {
		BadRequest(c, errMsg)
		return
	}
	if err := core.ValidateConfigRanges(req.Config); err != nil {
		BadRequest(c, err.Error())
		return
	}

	validProtocols := map[string]bool{"tcp": true, "udp": true, "http": true, "arp": true, "icmp": true, "dns": true, "ftp": true, "sip": true, "sctp": true}
	if req.Protocol == "" || !validProtocols[req.Protocol] {
		BadRequest(c, "invalid or missing protocol: "+req.Protocol)
		return
	}
	if err := core.ValidateProtocolSubConfigs(req.Config, req.Protocol); err != nil {
		BadRequest(c, err.Error())
		return
	}

	validFlowTypes := map[string]bool{"flows": true, "bps": true, "time": true}
	if !validFlowTypes[req.FlowControl.Type] {
		BadRequest(c, "invalid flow_control type: must be flows, bps, or time")
		return
	}
	if req.FlowControl.Value <= 0 {
		BadRequest(c, "flow_control value must be positive")
		return
	}

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
	configHash := calculateConfigHash(mode, req.Protocol, string(configJSON), string(flowControlJSON))

	var existing storage.StrategyModel
	if err := h.db.Where("user_id = ? AND config_hash = ?", userID, configHash).First(&existing).Error; err == nil {
		Success(c, map[string]string{"id": existing.ID, "message": "strategy already exists"})
		return
	}
	strategy := &storage.StrategyModel{
		ID:          uuid.New().String(),
		UserID:      userID,
		Name:        req.Name,
		Mode:        "synth",
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

		var taskCount int64
		h.db.Model(&storage.TaskModel{}).
			Where("user_id = ? AND EXISTS (SELECT 1 FROM json_each(strategy_ids) WHERE json_each.value = ?)", userID, s.ID).
			Count(&taskCount)

		result[i] = StrategyResponse{
			ID:          s.ID,
			UserID:      s.UserID,
			Name:        s.Name,
			Mode:        s.Mode,
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
		Mode:        strategy.Mode,
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

	// Determine mode: explicit request mode takes precedence; when omitted,
	// read the existing strategy's mode from DB (方案 A: preserve original
	// mode on updates that don't specify mode). If the strategy doesn't exist
	// or isn't owned, fall back to synth validation -- bad input still gets
	// 400 (STRAT4-BR2), good input gets 404 after validation.
	mode := req.Mode
	var strategy storage.StrategyModel
	dbLoaded := false
	if mode == "" {
		if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&strategy).Error; err == nil {
			dbLoaded = true
			mode = strategy.Mode
			if mode == "" {
				mode = "synth"
			}
		} else if err != gorm.ErrRecordNotFound {
			InternalError(c, "failed to get strategy: "+err.Error())
			return
		}
		// ErrRecordNotFound: mode stays "" -> defaults to synth below. Validation
		// runs, then 404 is returned post-validation (preserves STRAT4-BR2).
	}

	if mode == "" {
		mode = "synth"
	}

	// Validate request. When mode was provided explicitly, this runs BEFORE
	// the ownership check (STRAT4-BR2). When mode was empty, validation also
	// runs before the not-found response (bad input -> 400, good input -> 404).
	if mode == "replay" {
		configJSON, err := json.Marshal(req.Config)
		if err != nil {
			BadRequest(c, "invalid config format")
			return
		}
		if err := core.ValidateReplaySpec(json.RawMessage(configJSON)); err != nil {
			BadRequest(c, err.Error())
			return
		}
		if req.FlowControl != nil {
			if req.FlowControl.Type != "time" {
				BadRequest(c, "replay strategy flow_control only supports type=time")
				return
			}
			if req.FlowControl.Value <= 0 {
				BadRequest(c, "flow_control value must be positive")
				return
			}
		}
	} else {
		if errMsg := validateConfigNetwork(req.Config); errMsg != "" {
			BadRequest(c, errMsg)
			return
		}
		if err := core.ValidateConfigRanges(req.Config); err != nil {
			BadRequest(c, err.Error())
			return
		}
		validProtocols := map[string]bool{"tcp": true, "udp": true, "http": true, "arp": true, "icmp": true, "dns": true, "ftp": true, "sip": true, "sctp": true}
		if req.Protocol == "" || !validProtocols[req.Protocol] {
			BadRequest(c, "invalid or missing protocol: "+req.Protocol)
			return
		}
		if err := core.ValidateProtocolSubConfigs(req.Config, req.Protocol); err != nil {
			BadRequest(c, err.Error())
			return
		}
		if req.FlowControl != nil {
			validFlowTypes := map[string]bool{"flows": true, "bps": true, "time": true}
			if !validFlowTypes[req.FlowControl.Type] {
				BadRequest(c, "invalid flow_control type: must be flows, bps, or time")
				return
			}
			if req.FlowControl.Value <= 0 {
				BadRequest(c, "flow_control value must be positive")
				return
			}
		}
	}

	// If the empty-mode DB lookup failed (not found / not owned), return 404
	// now that validation has passed. Preserves STRAT4-BR2: bad input got 400
	// above; good input gets 404 here.
	if !dbLoaded && req.Mode == "" {
		NotFound(c, "strategy not found")
		return
	}

	// DB lookup if not already done above (mode was provided -> validate
	// first, then load). When mode was empty, the lookup already happened.
	if !dbLoaded {
		if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&strategy).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				NotFound(c, "strategy not found")
				return
			}
			InternalError(c, "failed to get strategy: "+err.Error())
			return
		}
	}

	if mode == "replay" {
		configJSON, err := json.Marshal(req.Config)
		if err != nil {
			BadRequest(c, "invalid config format")
			return
		}
		var flowControlJSON []byte
		if req.FlowControl != nil {
			flowControlJSON, err = json.Marshal(req.FlowControl)
			if err != nil {
				BadRequest(c, "invalid flow_control format")
				return
			}
		}
		strategy.Name = req.Name
		strategy.Mode = "replay"
		strategy.Protocol = ""
		strategy.Config = string(configJSON)
		strategy.FlowControl = string(flowControlJSON)
		strategy.ConfigHash = calculateConfigHash("replay", "", string(configJSON), string(flowControlJSON))
		if err := h.db.Save(&strategy).Error; err != nil {
			InternalError(c, "failed to update strategy: "+err.Error())
			return
		}
		SuccessWithMessage(c, "strategy updated", nil)
		return
	}

	// synth mode update (validation already done above)
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
	configHash := calculateConfigHash(mode, req.Protocol, string(configJSON), string(flowControlJSON))

	strategy.Name = req.Name
	strategy.Mode = "synth"
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

	var strategy storage.StrategyModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&strategy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "strategy not found")
			return
		}
		InternalError(c, "failed to get strategy: "+err.Error())
		return
	}

	var taskCount int64
	h.db.Model(&storage.TaskModel{}).
		Where("user_id = ? AND EXISTS (SELECT 1 FROM json_each(strategy_ids) WHERE json_each.value = ?)", userID, id).
		Count(&taskCount)
	if taskCount > 0 {
		BadRequest(c, "strategy is used by tasks, cannot delete")
		return
	}

	if err := h.db.Delete(&strategy).Error; err != nil {
		InternalError(c, "failed to delete strategy: "+err.Error())
		return
	}

	SuccessWithMessage(c, "strategy deleted", nil)
}

// calculateConfigHash calculates a hash for strategy configuration. mode is
// included so synth and replay configs with identical bodies get distinct
// hashes (they are distinct strategy types).
func calculateConfigHash(mode, protocol, config, flowControl string) string {
	data := mode + protocol + config + flowControl
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

	var strategy storage.StrategyModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&strategy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "strategy not found")
			return
		}
		InternalError(c, "failed to get strategy: "+err.Error())
		return
	}

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
