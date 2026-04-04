package rest

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"gorm.io/gorm"
)

// TaskHandler handles task requests.
type TaskHandler struct {
	db *storage.DB
}

// NewTaskHandler creates a new task handler.
func NewTaskHandler(db *storage.DB) *TaskHandler {
	return &TaskHandler{db: db}
}

// CreateTaskRequest represents a create task request.
type CreateTaskRequest struct {
	Name        string               `json:"name" binding:"required"`
	StrategyIDs []string             `json:"strategy_ids" binding:"required,min=1"`
	OutputType  string               `json:"output_type" binding:"required"` // "port_group" or "pcap"
	OutputConfig *OutputConfigRequest `json:"output_config" binding:"required"`
	FlowControl  *FlowControlRequest  `json:"flow_control"` // Optional, task-level flow control
}

// OutputConfigRequest represents output configuration.
type OutputConfigRequest struct {
	PortGroupID string `json:"port_group_id"` // For port_group output
	PcapPath    string `json:"pcap_path"`    // For pcap output
}

// TaskResponse represents a task response.
type TaskResponse struct {
	ID           string                `json:"id"`
	UserID       string                `json:"user_id"`
	Name         string                `json:"name"`
	StrategyIDs  []string              `json:"strategy_ids"`
	OutputType   string                `json:"output_type"`
	OutputConfig *OutputConfigRequest  `json:"output_config"`
	FlowControl  *FlowControlRequest   `json:"flow_control"`
	Status       string                `json:"status"`
	ErrorMessage string                `json:"error_message,omitempty"`
	Progress     float64               `json:"progress"`
	CreatedAt    int64                 `json:"created_at"`
	UpdatedAt    int64                 `json:"updated_at"`
	StartedAt    *int64                `json:"started_at,omitempty"`
	CompletedAt  *int64                `json:"completed_at,omitempty"`
}

// Create creates a new task (idempotent).
func (h *TaskHandler) Create(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Validate output configuration
	if req.OutputType == "port_group" && req.OutputConfig.PortGroupID == "" {
		BadRequest(c, "port_group_id is required for port_group output")
		return
	}
	if req.OutputType == "pcap" && req.OutputConfig.PcapPath == "" {
		BadRequest(c, "pcap_path is required for pcap output")
		return
	}

	// Validate strategy IDs
	for _, strategyID := range req.StrategyIDs {
		var strategy storage.StrategyModel
		if err := h.db.Where("id = ? AND user_id = ?", strategyID, userID).First(&strategy).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				BadRequest(c, fmt.Sprintf("strategy %s not found", strategyID))
				return
			}
			InternalError(c, "failed to validate strategy: "+err.Error())
			return
		}
	}

	// Serialize for storage
	strategyIDsJSON, _ := json.Marshal(req.StrategyIDs)
	outputConfigJSON, _ := json.Marshal(req.OutputConfig)
	var flowControlJSON []byte
	if req.FlowControl != nil {
		flowControlJSON, _ = json.Marshal(req.FlowControl)
	}

	// Calculate hash for idempotent creation
	sortedStrategyIDs := make([]string, len(req.StrategyIDs))
	copy(sortedStrategyIDs, req.StrategyIDs)
	sort.Strings(sortedStrategyIDs)
	_ = calculateTaskHash(sortedStrategyIDs, string(outputConfigJSON)) // For future use

	// Check if task already exists
	var existingTask storage.TaskModel
	if err := h.db.Where("user_id = ? AND strategy_ids = ?", userID, string(strategyIDsJSON)).First(&existingTask).Error; err == nil {
		// Task exists, return existing ID
		Success(c, map[string]string{
			"id":      existingTask.ID,
			"message": "task already exists",
		})
		return
	}

	// Create new task
	task := &storage.TaskModel{
		ID:           uuid.New().String(),
		UserID:       userID,
		Name:         req.Name,
		StrategyIDs:  string(strategyIDsJSON),
		OutputType:   req.OutputType,
		OutputConfig: string(outputConfigJSON),
		FlowControl:  string(flowControlJSON),
		Status:       "pending",
		Progress:     0,
	}

	if err := h.db.Create(task).Error; err != nil {
		InternalError(c, "failed to create task: "+err.Error())
		return
	}

	Created(c, map[string]string{"id": task.ID})
}

// List lists all tasks for the current user.
func (h *TaskHandler) List(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var tasks []storage.TaskModel
	if err := h.db.Where("user_id = ?", userID).Find(&tasks).Error; err != nil {
		InternalError(c, "failed to list tasks: "+err.Error())
		return
	}

	result := make([]TaskResponse, len(tasks))
	for i, t := range tasks {
		result[i] = convertTaskToResponse(&t)
	}

	Success(c, result)
}

// Get gets a task by ID.
func (h *TaskHandler) Get(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing task id")
		return
	}

	var task storage.TaskModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "task not found")
			return
		}
		InternalError(c, "failed to get task: "+err.Error())
		return
	}

	Success(c, convertTaskToResponse(&task))
}

// Start starts a task.
func (h *TaskHandler) Start(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing task id")
		return
	}

	var task storage.TaskModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "task not found")
			return
		}
		InternalError(c, "failed to get task: "+err.Error())
		return
	}

	// Check if task is already running
	if task.Status == "running" {
		BadRequest(c, "task is already running")
		return
	}

	// Validate all strategies exist
	var strategyIDs []string
	json.Unmarshal([]byte(task.StrategyIDs), &strategyIDs)

	for _, strategyID := range strategyIDs {
		var strategy storage.StrategyModel
		if err := h.db.Where("id = ? AND user_id = ?", strategyID, userID).First(&strategy).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				task.Status = "error"
				task.ErrorMessage = fmt.Sprintf("strategy %s not found", strategyID)
				h.db.Save(&task)
				BadRequest(c, task.ErrorMessage)
				return
			}
			InternalError(c, "failed to validate strategy: "+err.Error())
			return
		}
	}

	// Validate port group if needed
	if task.OutputType == "port_group" {
		var outputConfig OutputConfigRequest
		json.Unmarshal([]byte(task.OutputConfig), &outputConfig)

		var portGroup storage.PortGroupModel
		if err := h.db.Where("id = ?", outputConfig.PortGroupID).First(&portGroup).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				task.Status = "error"
				task.ErrorMessage = "port group not found"
				h.db.Save(&task)
				BadRequest(c, task.ErrorMessage)
				return
			}
			InternalError(c, "failed to validate port group: "+err.Error())
			return
		}

		// Check port status
		var portsConfig []map[string]interface{}
		json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig)

		for _, portConfig := range portsConfig {
			if iface, ok := portConfig["interface"].(string); ok {
				var port storage.PortModel
				if err := h.db.Where("name = ?", iface).First(&port).Error; err == nil {
					if port.Status == "using" && port.CurrentTaskID != id {
						task.Status = "error"
						task.ErrorMessage = fmt.Sprintf("port %s is in use by another task", iface)
						h.db.Save(&task)
						BadRequest(c, task.ErrorMessage)
						return
					}
				}
			}
		}
	}

	// TODO: Actually start the task execution
	// This will be implemented in the engine

	task.Status = "running"
	now := currentTime()
	task.StartedAt = &now
	h.db.Save(&task)

	SuccessWithMessage(c, "task started", nil)
}

// Stop stops a task.
func (h *TaskHandler) Stop(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing task id")
		return
	}

	var task storage.TaskModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "task not found")
			return
		}
		InternalError(c, "failed to get task: "+err.Error())
		return
	}

	// Check if task is running
	if task.Status != "running" {
		BadRequest(c, "task is not running")
		return
	}

	// TODO: Actually stop the task execution
	// This will be implemented in the engine

	task.Status = "stopped"
	now := currentTime()
	task.CompletedAt = &now
	h.db.Save(&task)

	// Release port status
	if task.OutputType == "port_group" {
		var outputConfig OutputConfigRequest
		json.Unmarshal([]byte(task.OutputConfig), &outputConfig)

		var portGroup storage.PortGroupModel
		if err := h.db.Where("id = ?", outputConfig.PortGroupID).First(&portGroup).Error; err == nil {
			var portsConfig []map[string]interface{}
			json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig)

			for _, portConfig := range portsConfig {
				if iface, ok := portConfig["interface"].(string); ok {
					h.db.Model(&storage.PortModel{}).
						Where("name = ? AND current_task_id = ?", iface, id).
						Updates(map[string]interface{}{
							"status":          "idle",
							"current_task_id": "",
						})
				}
			}
		}
	}

	SuccessWithMessage(c, "task stopped", nil)
}

// Delete deletes a task.
func (h *TaskHandler) Delete(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing task id")
		return
	}

	var task storage.TaskModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "task not found")
			return
		}
		InternalError(c, "failed to get task: "+err.Error())
		return
	}

	// Check if task is running
	if task.Status == "running" {
		BadRequest(c, "cannot delete running task, stop it first")
		return
	}

	// Delete task
	if err := h.db.Delete(&task).Error; err != nil {
		InternalError(c, "failed to delete task: "+err.Error())
		return
	}

	SuccessWithMessage(c, "task deleted", nil)
}

// convertTaskToResponse converts a TaskModel to TaskResponse.
func convertTaskToResponse(t *storage.TaskModel) TaskResponse {
	var strategyIDs []string
	json.Unmarshal([]byte(t.StrategyIDs), &strategyIDs)

	var outputConfig OutputConfigRequest
	json.Unmarshal([]byte(t.OutputConfig), &outputConfig)

	var flowControl *FlowControlRequest
	if t.FlowControl != "" {
		flowControl = &FlowControlRequest{}
		json.Unmarshal([]byte(t.FlowControl), flowControl)
	}

	response := TaskResponse{
		ID:           t.ID,
		UserID:       t.UserID,
		Name:         t.Name,
		StrategyIDs:  strategyIDs,
		OutputType:   t.OutputType,
		OutputConfig: &outputConfig,
		FlowControl:  flowControl,
		Status:       t.Status,
		ErrorMessage: t.ErrorMessage,
		Progress:     t.Progress,
		CreatedAt:    t.CreatedAt.Unix(),
		UpdatedAt:    t.UpdatedAt.Unix(),
	}

	if t.StartedAt != nil {
		startedAt := t.StartedAt.Unix()
		response.StartedAt = &startedAt
	}

	if t.CompletedAt != nil {
		completedAt := t.CompletedAt.Unix()
		response.CompletedAt = &completedAt
	}

	return response
}

// calculateTaskHash calculates a hash for task configuration.
func calculateTaskHash(strategyIDs []string, outputConfig string) string {
	data := ""
	for _, id := range strategyIDs {
		data += id
	}
	data += outputConfig
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// currentTime returns current time (helper for testing).
func currentTime() time.Time {
	return time.Now()
}
