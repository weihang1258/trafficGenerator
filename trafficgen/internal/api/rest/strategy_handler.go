package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"gorm.io/gorm"
)

// toSchemaFC converts the REST flow-control request to the schema entry view.
// nil stays nil (absent envelope, not a zero value).
func toSchemaFC(fc *FlowControlRequest) *schema.FlowControl {
	if fc == nil {
		return nil
	}
	return &schema.FlowControl{Type: fc.Type, Value: fc.Value}
}

// schemaGate runs the unified strategy validation entry and writes the 400 on
// failure. It returns the effective protocol and false when rejected.
func schemaGate(c *gin.Context, mode, protocol string, config map[string]interface{}, fc *FlowControlRequest) (string, bool) {
	eff, errs := schema.ValidateStrategy(mode, protocol, config, toSchemaFC(fc))
	if len(errs) > 0 {
		BadRequest(c, errs.Error())
		return eff, false
	}
	return eff, true
}

// Validate strategy requests.
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

	// P0-1（2026-10-05 客户端复测）：内嵌 config.flow_control 必须生效——
	// 层链 config 是唯一配置真相，此前该键全仓库无消费者，flows=2000/bps=
	// 50000 的声明全部静默走 flows:1 缺省（P0-2 的"coerce"同源）。顶层参数
	// 显式给定时覆盖内嵌；形状错误在此报，type/value 语义交给 schemaGate
	// （与顶层同一 canonical 文案）。ReplaySpec 无内嵌 flow_control。
	if req.FlowControl == nil && mode != "replay" {
		fc, err := embeddedFlowControl(req.Config)
		if err != nil {
			BadRequest(c, err.Error())
			return
		}
		req.FlowControl = fc
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

// embeddedFlowControl extracts config["flow_control"] so the embedded key
// takes effect (P0-1: the layer-chain config is the single source of truth).
// Returns (nil, nil) when the key is absent or explicit null; a non-object
// value is a shape error reported here. Type/value semantics stay with the
// schema gate, which already owns the canonical wording for the top-level
// parameter — an embedded invalid value fails with that same text.
func embeddedFlowControl(config map[string]interface{}) (*FlowControlRequest, error) {
	raw, ok := config["flow_control"]
	if !ok || raw == nil {
		return nil, nil
	}
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("config.flow_control must be an object {\"type\":\"flows|bps|time\",\"value\":N}")
	}
	fc := &FlowControlRequest{}
	if t, ok := obj["type"].(string); ok {
		fc.Type = t
	}
	if v, ok := obj["value"].(float64); ok {
		fc.Value = v
	}
	return fc, nil
}

// createReplayStrategy validates + persists a replay-mode strategy. Skips all
// synth-specific validation (network/ranges/protocol/sub-configs); the config
// is validated as a ReplaySpec instead. Strategy-level flow_control only
// accepts "time" (flows is unsupported, bps folds into speed.mode).
func (h *StrategyHandler) createReplayStrategy(c *gin.Context, userID string, req *CreateStrategyRequest) {
	// Unified schema gate (shape + replay semantics incl. layers rejection,
	// replay-spec validity, time-only flow control). Messages preserved.
	if _, ok := schemaGate(c, "replay", "", req.Config, req.FlowControl); !ok {
		return
	}
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
	// Unified schema gate (shape + network formats, ranges, layers inference,
	// protocol allowlist, sub-config ranges, TFTP tid rule). Inferred protocol
	// is written back, same as the old inline ValidateLayers block.
	eff, ok := schemaGate(c, "synth", req.Protocol, req.Config, req.FlowControl)
	if !ok {
		return
	}
	req.Protocol = eff

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

	// P0-1: same embedded extraction as Create — a full replace carries a
	// fresh config whose embedded flow_control must take effect when the
	// top-level parameter is omitted. Synth only (ReplaySpec has none).
	if req.FlowControl == nil && mode != "replay" {
		fc, err := embeddedFlowControl(req.Config)
		if err != nil {
			BadRequest(c, err.Error())
			return
		}
		req.FlowControl = fc
	}

	// Unified schema gate (same entry as create paths: shape + full semantics,
	// mode-aware). Preserves STRAT4-BR2 ordering: bad input -> 400 before any
	// ownership/404 handling below.
	effProto, gateOK := schemaGate(c, mode, req.Protocol, req.Config, req.FlowControl)
	if !gateOK {
		return
	}
	req.Protocol = effProto

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

// validateIP checks that a string is a valid IPv4 or IPv6 address.
// net.ParseIP handles both formats: dotted-quad (e.g. "10.0.0.1") and
// colon-hex (e.g. "2001:db8::1", "::1", "fe80::1"). Previously this function
// used an IPv4-only regex, which blocked IPv6 strategies at the MCP layer
// even though the planner pipeline already supports IPv6 end-to-end.
func validateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// validateMAC checks that a string is a valid MAC address (XX:XX:XX:XX:XX:XX).
func validateMAC(mac string) bool {
	return regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`).MatchString(mac)
}

// validateConfigNetwork is retired from live paths (schema entry owns
// network-format checks via validateConfigNetworkLocal). Kept because
// validation_testpoints_test.go pins its behavior; delete together.
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
