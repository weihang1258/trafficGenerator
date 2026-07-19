package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/output"
	"github.com/trafficgen/trafficgen/internal/api/websocket"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"github.com/trafficgen/trafficgen/pkg/netif"
	"gorm.io/gorm"
)

// TaskHandler handles task requests.
type TaskHandler struct {
	db          *storage.DB
	engine      *core.Engine
	wsHub       *websocket.Hub
	failedTasks map[string]string // engineTaskID -> errorMessage
	failMu      sync.Mutex
	lastProgressUpdate map[string]time.Time // parentTaskID -> last DB update time
	progressMu        sync.Mutex
}

// NewTaskHandler creates a new task handler and registers engine callbacks.
func NewTaskHandler(db *storage.DB, engine *core.Engine, wsHandler *websocket.Handler) *TaskHandler {
	return NewTaskHandlerWithCallbacks(db, engine, wsHandler, true)
}

// NewTaskHandlerWithCallbacks creates a TaskHandler. If registerCallbacks is
// false, engine callback fields (OnTaskComplete/OnTaskFailed/OnOutputError/
// OnProgress) are NOT overwritten -- used by MCP server to avoid clobbering
// the REST server's callbacks when it creates its own TaskHandler instance
// for direct method invocation.
func NewTaskHandlerWithCallbacks(db *storage.DB, engine *core.Engine, wsHandler *websocket.Handler, registerCallbacks bool) *TaskHandler {
	var hub *websocket.Hub
	if wsHandler != nil {
		hub = wsHandler.Hub()
	}
	h := &TaskHandler{
		db:                db,
		engine:            engine,
		wsHub:             hub,
		failedTasks:       make(map[string]string),
		lastProgressUpdate: make(map[string]time.Time),
	}

	if registerCallbacks {
		// Register engine completion callback to update DB status
		engine.OnTaskComplete = h.onEngineTaskComplete

		// Register task failed callback to record error messages
		engine.OnTaskFailed = h.onEngineTaskFailed

		// Register output error callback to fail tasks on write errors
		engine.OnOutputError = h.onEngineOutputError

		// Register progress callback for continuous progress tracking
		engine.OnProgress = h.onEngineProgress
	}

	return h
}

// onEngineTaskFailed is called when an engine task fails (planning error, etc.).
func (h *TaskHandler) onEngineTaskFailed(engineTaskID string, errMsg string) {
	h.failMu.Lock()
	h.failedTasks[engineTaskID] = errMsg
	h.failMu.Unlock()
}

// onEngineOutputError is called when an output writer fails.
func (h *TaskHandler) onEngineOutputError(engineTaskID string, writeErr error) {
	taskID := engineTaskID
	if len(engineTaskID) > 37 {
		taskID = engineTaskID[:36]
	}

	log.Printf("output error for engine task %s: %v, failing task %s", engineTaskID, writeErr, taskID)

	// Record the failure before failing the engine task (FailTask triggers onEngineTaskComplete)
	h.failMu.Lock()
	h.failedTasks[engineTaskID] = writeErr.Error()
	h.failMu.Unlock()

	// Fail the engine task
	h.engine.FailTask(engineTaskID, writeErr.Error())

	// Unregister the broken writer
	h.engine.UnregisterOutputWriter(engineTaskID)
}

// onEngineProgress is called by the engine when task progress changes (>1% delta).
// It debounces DB updates to at most once per 2 seconds per parent task.
func (h *TaskHandler) onEngineProgress(engineTaskID string, progress float64, stats core.TaskStats) {
	// Extract parent task ID from composite engine task ID "{taskID}-{strategyID}"
	parts := strings.SplitN(engineTaskID, "-", 2)
	parentTaskID := engineTaskID
	if len(parts) == 2 {
		parentTaskID = parts[0]
	}

	// Throttle DB updates: at most once per 2 seconds per parent task
	h.progressMu.Lock()
	lastUpdate, exists := h.lastProgressUpdate[parentTaskID]
	now := time.Now()
	if exists && now.Sub(lastUpdate) < 2*time.Second {
		h.progressMu.Unlock()
		return
	}
	h.lastProgressUpdate[parentTaskID] = now
	h.progressMu.Unlock()

	// Calculate aggregate progress for the parent task
	// Get all engine sub-tasks from the task store and average their progress.
	// NOTE: Progress values read within RangeTaskStore are approximate snapshots;
	// concurrent updates may cause slight inconsistency, which is acceptable
	// given the 2-second throttle and 1% granularity.
	totalProgress := progress
	subTaskCount := 1

	// Try to find other sub-tasks for the same parent
	h.engine.RangeTaskStore(func(id string, status *core.TaskStatus) bool {
		parts2 := strings.SplitN(id, "-", 2)
		if len(parts2) == 2 && parts2[0] == parentTaskID && id != engineTaskID {
			totalProgress += status.Progress
			subTaskCount++
		}
		return true
	})

	avgProgress := totalProgress / float64(subTaskCount)

	// Update parent task progress in DB
	h.db.Model(&storage.TaskModel{}).
		Where("id = ?", parentTaskID).
		Updates(map[string]interface{}{
			"progress": avgProgress,
		})

	// Broadcast progress update via WebSocket
	if h.wsHub != nil {
		h.wsHub.BroadcastToTask(parentTaskID, websocket.Message{
			Type:      websocket.TypeProgressUpdate,
			Data: map[string]interface{}{
				"task_id":  parentTaskID,
				"progress": avgProgress,
				"stats":    stats,
			},
		})
	}
}

// onEngineTaskComplete is called by the engine when a task finishes (completed or failed).
// The engine task ID format is "{taskID}-{strategyID}", so we extract the parent task ID.
// Batch tasks are a special case: their engine task ID == task ID (no suffix), and
// they use BatchConfig instead of StrategyIDs — so the strategyIDs loop below would
// no-op and we'd miss the failure-message collection path.
func (h *TaskHandler) onEngineTaskComplete(engineTaskID string) {
	// Extract parent task ID (format: {taskID}-{strategyID}, where taskID is a UUID)
	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
	// Engine task ID: {36-char-uuid}-{strategy-uuid}
	taskID := engineTaskID
	if len(engineTaskID) > 37 {
		taskID = engineTaskID[:36]
	}

	var task storage.TaskModel
	if err := h.db.Where("id = ?", taskID).First(&task).Error; err != nil {
		log.Printf("onEngineTaskComplete: task %s not found in DB: %v", taskID, err)
		return
	}

	// Batch tasks: single engine task, ID == taskID. Skip the strategyIDs
	// loop (empty by design) and check this engine task directly.
	if task.BatchConfig != "" {
		// Engine task still running -> not done yet.
		if _, err := h.engine.GetTaskStatus(taskID); err == nil {
			return
		}
		if task.Status != "running" {
			return
		}
		now := currentTime()
		task.CompletedAt = &now

		h.failMu.Lock()
		var failMsgs []string
		if errMsg, ok := h.failedTasks[taskID]; ok {
			failMsgs = append(failMsgs, fmt.Sprintf("%s: %s", taskID, errMsg))
			delete(h.failedTasks, taskID)
		}
		h.failMu.Unlock()

		if len(failMsgs) > 0 {
			task.Status = "failed"
			task.ErrorMessage = fmt.Sprintf("output error: %v", failMsgs)
			log.Printf("batch task %s marked as failed in DB: %s", taskID, task.ErrorMessage)
		} else {
			task.Status = "completed"
			task.Progress = 100
			log.Printf("batch task %s marked as completed in DB", taskID)
		}
		h.db.Save(&task)

		if h.wsHub != nil {
			msgType := websocket.TypeTaskCompleted
			if task.Status == "failed" {
				msgType = websocket.TypeTaskFailed
			}
			h.wsHub.BroadcastToTask(taskID, websocket.Message{
				Type:      msgType,
				Data: map[string]interface{}{
					"task_id":  taskID,
					"status":   task.Status,
					"progress": task.Progress,
				},
			})
		}

		h.releasePortGroupPorts(&task)
		h.engine.UnregisterOutputWriter(taskID)
		h.engine.UnregisterDualWriter(taskID)
		h.engine.CleanupTaskFlowControl(taskID)
		return
	}

	// Check if all engine tasks for this task are done
	var strategyIDs []string
	json.Unmarshal([]byte(task.StrategyIDs), &strategyIDs)

	allDone := true
	for _, sid := range strategyIDs {
		eid := fmt.Sprintf("%s-%s", taskID, sid)
		if _, err := h.engine.GetTaskStatus(eid); err == nil {
			// Still in taskStore = still running
			allDone = false
			break
		}
	}

	if allDone && task.Status == "running" {
		now := currentTime()
		task.CompletedAt = &now

		// Check if any engine task failed
		h.failMu.Lock()
		var failMsgs []string
		for _, sid := range strategyIDs {
			eid := fmt.Sprintf("%s-%s", taskID, sid)
			if errMsg, ok := h.failedTasks[eid]; ok {
				failMsgs = append(failMsgs, fmt.Sprintf("%s: %s", eid, errMsg))
				delete(h.failedTasks, eid)
			}
		}
		h.failMu.Unlock()

		if len(failMsgs) > 0 {
			task.Status = "failed"
			task.ErrorMessage = fmt.Sprintf("output error: %v", failMsgs)
			log.Printf("task %s marked as failed in DB: %s", taskID, task.ErrorMessage)
		} else {
			task.Status = "completed"
			task.Progress = 100
			log.Printf("task %s marked as completed in DB", taskID)
		}
		h.db.Save(&task)

		// Broadcast task completion via WebSocket
		if h.wsHub != nil {
			msgType := websocket.TypeTaskCompleted
			if task.Status == "failed" {
				msgType = websocket.TypeTaskFailed
			}
			h.wsHub.BroadcastToTask(taskID, websocket.Message{
				Type:      msgType,
				Data: map[string]interface{}{
					"task_id":  taskID,
					"status":   task.Status,
					"progress": task.Progress,
				},
			})
		}

		// Release port group ports
		h.releasePortGroupPorts(&task)

		// Unregister output writers (and dual-writers, if any) for all engine tasks
		for _, sid := range strategyIDs {
			eid := fmt.Sprintf("%s-%s", taskID, sid)
			h.engine.UnregisterOutputWriter(eid)
			h.engine.UnregisterDualWriter(eid)
		}
		// Batch tasks register a single writer under the plain taskID
		// (no strategy suffix); unregister it too. No-op for strategy tasks.
		h.engine.UnregisterOutputWriter(taskID)
		h.engine.UnregisterDualWriter(taskID)

		// Clean up task-level flow control state (parent rate bucket +
		// shared flow counter). Safe no-op when no ceiling was set.
		h.engine.CleanupTaskFlowControl(taskID)
	}
}

// releasePortGroupPorts releases ports allocated for a task's port group.
func (h *TaskHandler) releasePortGroupPorts(task *storage.TaskModel) {
	if task.OutputType != "port_group" {
		return
	}
	var outputConfig OutputConfigRequest
	json.Unmarshal([]byte(task.OutputConfig), &outputConfig)

	var portGroup storage.PortGroupModel
	if err := h.db.Where("id = ?", outputConfig.PortGroupID).First(&portGroup).Error; err != nil {
		return
	}

	var portsConfig []map[string]interface{}
	json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig)

	for _, portConfig := range portsConfig {
		if iface, ok := portConfig["interface"].(string); ok {
			h.db.Model(&storage.PortModel{}).
				Where("name = ? AND current_task_id = ?", iface, task.ID).
				Updates(map[string]interface{}{
					"status":          "idle",
					"current_task_id": "",
				})
		}
	}
}

// ensureTaskMTU ensures every NIC the task will write to has MTU >=
// engine.min_mtu. Returns the list of interfaces it was asked to check
// (for error reporting) and an error if any raise failed. For port_group
// output this walks every interface in the group; for dual-port replay it
// also checks interface2. pcap output is skipped (no NIC involved). On
// raise failure the caller must mark the task failed -- the operator
// needs to either run as root or lower engine.min_mtu.
func (h *TaskHandler) ensureTaskMTU(task *storage.TaskModel, interface2 string) ([]string, error) {
	minMTU := h.engine.MinMTU()
	if minMTU <= 0 {
		return nil, nil
	}
	if task.OutputType != "port_group" {
		// pcap output doesn't touch a NIC.
		return nil, nil
	}
	var outputConfig OutputConfigRequest
	if err := json.Unmarshal([]byte(task.OutputConfig), &outputConfig); err != nil {
		return nil, fmt.Errorf("corrupt output_config: %w", err)
	}
	var portGroup storage.PortGroupModel
	if err := h.db.Where("id = ?", outputConfig.PortGroupID).First(&portGroup).Error; err != nil {
		return nil, fmt.Errorf("port group %s not found: %w", outputConfig.PortGroupID, err)
	}
	var portsConfig []map[string]interface{}
	if err := json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig); err != nil {
		return nil, fmt.Errorf("corrupt ports_config in port group %s: %w", portGroup.ID, err)
	}
	var ifaces []string
	seen := make(map[string]bool)
	for _, portConfig := range portsConfig {
		if iface, ok := portConfig["interface"].(string); ok && iface != "" && !seen[iface] {
			seen[iface] = true
			ifaces = append(ifaces, iface)
		}
	}
	if interface2 != "" && !seen[interface2] {
		ifaces = append(ifaces, interface2)
	}
	for _, iface := range ifaces {
		if err := netif.EnsureMTU(iface, minMTU); err != nil {
			return ifaces, fmt.Errorf("MTU raise failed for %s: %w", iface, err)
		}
	}
	return ifaces, nil
}

// CreateTaskRequest represents a create task request.
type CreateTaskRequest struct {
	Name        string               `json:"name" binding:"required"`
	StrategyIDs []string             `json:"strategy_ids" binding:"required,min=1"`
	OutputType  string               `json:"output_type" binding:"required"` // "port_group" or "pcap"
	OutputConfig *OutputConfigRequest `json:"output_config" binding:"required"`
	FlowControl  *FlowControlRequest  `json:"flow_control"` // Optional, task-level flow control
}

// CreateBatchTaskRequest represents a mixed-traffic batch task request. The
// caller supplies a full BatchSpec (multiple protocol classes) inline rather
// than referencing saved strategies.
type CreateBatchTaskRequest struct {
	Name         string               `json:"name" binding:"required"`
	Batch        *core.BatchSpec      `json:"batch" binding:"required"`
	OutputType   string               `json:"output_type" binding:"required"` // "port_group" or "pcap"
	OutputConfig *OutputConfigRequest `json:"output_config" binding:"required"`
}

// OutputConfigRequest represents output configuration.
type OutputConfigRequest struct {
	PortGroupID string `json:"port_group_id"` // For port_group output
	PcapPath    string `json:"pcap_path"`    // For pcap output
	Interface2  string `json:"interface2,omitempty"` // Second interface for dual-port replay (§16.11)
}

// TaskStatsResponse represents task statistics in the response.
type TaskStatsResponse struct {
	PacketsSent int64   `json:"packets_sent"`
	BytesSent   int64   `json:"bytes_sent"`
	FlowsCount  int64   `json:"flows_count"`
	CurrentPPS  float64 `json:"current_pps"`
	CurrentBPS  float64 `json:"current_bps"`
}

// StrategyBrief represents a strategy summary in the task response.
type StrategyBrief struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Mode        string               `json:"mode,omitempty"`
	Protocol    string               `json:"protocol"`
	FlowControl *FlowControlRequest  `json:"flow_control,omitempty"`
}

// TaskResponse represents a task response.
type TaskResponse struct {
	ID           string                `json:"id"`
	UserID       string                `json:"user_id"`
	Name         string                `json:"name"`
	Protocol     string                `json:"protocol,omitempty"`
	StrategyIDs  []string              `json:"strategy_ids"`
	Strategies   []StrategyBrief       `json:"strategies,omitempty"`
	OutputType   string                `json:"output_type"`
	OutputConfig *OutputConfigRequest  `json:"output_config"`
	FlowControl  *FlowControlRequest   `json:"flow_control"`
	Status       string                `json:"status"`
	ErrorMessage string                `json:"error_message,omitempty"`
	Progress     float64               `json:"progress"`
	Stats        *TaskStatsResponse    `json:"stats,omitempty"`
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

	// Validate strategy_ids
	if len(req.StrategyIDs) == 0 {
		BadRequest(c, "at least one strategy_id is required")
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

	// Validate task-level flow control (if provided).
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

	// Validate strategy IDs and capture primary protocol
	var primaryProtocol string
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
		if primaryProtocol == "" {
			primaryProtocol = strategy.Protocol
		}
	}

	// Collect strategies for replay+bps conflict check (needed below)
	strategiesForFC := make([]storage.StrategyModel, 0, len(req.StrategyIDs))
	for _, strategyID := range req.StrategyIDs {
		var strategy storage.StrategyModel
		if err := h.db.Where("id = ? AND user_id = ?", strategyID, userID).First(&strategy).Error; err != nil {
			// already validated above, skip on error
			continue
		}
		strategiesForFC = append(strategiesForFC, strategy)
	}
	if err := validateReplayBPSConflict(strategiesForFC, req.FlowControl); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Serialize for storage
	outputConfigJSON, _ := json.Marshal(req.OutputConfig)
	var flowControlJSON []byte
	if req.FlowControl != nil {
		flowControlJSON, _ = json.Marshal(req.FlowControl)
	}

	// Sort strategy IDs for consistent idempotency checks AND canonical storage,
	// so a duplicate submission with reversed order still hits the same record.
	sortedStrategyIDs := make([]string, len(req.StrategyIDs))
	copy(sortedStrategyIDs, req.StrategyIDs)
	sort.Strings(sortedStrategyIDs)
	sortedStrategyIDsJSON, _ := json.Marshal(sortedStrategyIDs)

	// Check if an ACTIVE task already exists with same config for this user.
	// FlowControl is part of the identity: different ceilings = different task.
	var existingTask storage.TaskModel
	if err := h.db.Where("user_id = ? AND strategy_ids = ? AND output_config = ? AND flow_control = ? AND status IN ?",
		userID, string(sortedStrategyIDsJSON), string(outputConfigJSON), string(flowControlJSON),
		[]string{"pending", "running"}).First(&existingTask).Error; err == nil {
		Success(c, map[string]string{
			"id":      existingTask.ID,
			"message": "task already exists",
		})
		return
	}

	// Create new task. Store the SORTED strategy_ids so idempotency lookups
	// (which query by sorted form) match regardless of insertion order.
	task := &storage.TaskModel{
		ID:           uuid.New().String(),
		UserID:       userID,
		Name:         req.Name,
		StrategyIDs:  string(sortedStrategyIDsJSON),
		Protocol:     primaryProtocol,
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

// CreateBatch creates and immediately starts a mixed-traffic batch task. The
// BatchSpec runs multiple protocol classes concurrently in one engine task.
// POST /api/v1/tasks/batch
func (h *TaskHandler) CreateBatch(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var req CreateBatchTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}
	if req.Batch == nil || len(req.Batch.Classes) == 0 {
		BadRequest(c, "batch must contain at least one traffic class")
		return
	}

	// Validate output configuration.
	if req.OutputType == "port_group" && req.OutputConfig.PortGroupID == "" {
		BadRequest(c, "port_group_id is required for port_group output")
		return
	}
	if req.OutputType == "pcap" && req.OutputConfig.PcapPath == "" {
		BadRequest(c, "pcap_path is required for pcap output")
		return
	}

	taskID := uuid.New().String()

	// Resolve output: interface name for port_group, resolved path for pcap.
	outputMode := "pcap"
	iface := ""
	pcapFile := ""
	if req.OutputType == "port_group" {
		outputMode = "interface"
		var portGroup storage.PortGroupModel
		if err := h.db.Where("id = ?", req.OutputConfig.PortGroupID).First(&portGroup).Error; err != nil {
			BadRequest(c, "port group not found: "+req.OutputConfig.PortGroupID)
			return
		}
		var portsConfig []map[string]interface{}
		json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig)
		if len(portsConfig) > 0 {
			if i, ok := portsConfig[0]["interface"].(string); ok {
				iface = i
			}
		}
		if iface == "" {
			BadRequest(c, "port group has no interface configured")
			return
		}
	} else {
		resolved, err := resolvePcapPath(req.OutputConfig.PcapPath)
		if err != nil {
			BadRequest(c, err.Error())
			return
		}
		pcapFile = resolved
	}

	// Detect dual-port replay: a replay class with direction="dual" OR an
	// explicit interface2 in the output config (§16.11). Dual-port routes c2s
	// packets to the primary interface and s2c to the second.
	dualPort := req.OutputConfig != nil && req.OutputConfig.Interface2 != ""
	if !dualPort {
		for _, class := range req.Batch.Classes {
			if class.Type == "replay" && len(class.Replay) > 0 {
				var rs struct {
					Direction string `json:"direction"`
				}
				if json.Unmarshal(class.Replay, &rs) == nil && rs.Direction == "dual" {
					dualPort = true
					break
				}
			}
		}
	}
	if dualPort && outputMode == "interface" && (req.OutputConfig == nil || req.OutputConfig.Interface2 == "") {
		BadRequest(c, "dual-port replay requires a second interface (interface2 in output_config)")
		return
	}

	// Create + register the output writer BEFORE submitting (avoids race).
	var writer core.PacketWriter
	var err error
	if outputMode == "interface" {
		writer, err = newInterfacePacketWriter(iface)
	} else {
		writer, err = newPcapPacketWriter(pcapFile)
	}
	if err != nil {
		InternalError(c, "failed to create output writer: "+err.Error())
		return
	}
	if dualPort {
		// Register a dual-port writer pair: c2s -> primary, s2c -> secondary.
		var writer2 core.PacketWriter
		if outputMode == "interface" {
			writer2, err = newInterfacePacketWriter(req.OutputConfig.Interface2)
		} else {
			// Dual-file pcap output: append ".s2c" to the pcap path.
			writer2, err = newPcapPacketWriter(pcapFile + ".s2c")
		}
		if err != nil {
			writer.Close()
			InternalError(c, "failed to create second output writer: "+err.Error())
			return
		}
		h.engine.RegisterDualWriter(taskID, writer, writer2)
	} else {
		h.engine.RegisterOutputWriter(taskID, writer)
	}

	// Persist a task record (StrategyIDs empty; BatchConfig holds the spec).
	batchJSON, _ := json.Marshal(req.Batch)
	outputConfigJSON, _ := json.Marshal(req.OutputConfig)
	now := currentTime()
	taskModel := &storage.TaskModel{
		ID:           taskID,
		UserID:       userID,
		Name:         req.Name,
		Protocol:     "batch",
		BatchConfig:  string(batchJSON),
		OutputType:   req.OutputType,
		OutputConfig: string(outputConfigJSON),
		Status:       "running",
		StartedAt:    &now,
	}
	if err := h.db.Create(taskModel).Error; err != nil {
		h.engine.UnregisterOutputWriter(taskID)
		InternalError(c, "failed to create task record: "+err.Error())
		return
	}

	// Raise NIC MTU if engine.min_mtu is configured. Done AFTER the task
	// record is persisted (so a failure leaves a clear audit trail) but
	// BEFORE SubmitTask (so the engine never sees a task whose NIC can't
	// fit the packets). On failure the task is marked failed.
	interface2ForDual := ""
	if dualPort && req.OutputConfig != nil {
		interface2ForDual = req.OutputConfig.Interface2
	}
	if _, err := h.ensureTaskMTU(taskModel, interface2ForDual); err != nil {
		taskModel.Status = "error"
		taskModel.ErrorMessage = err.Error()
		h.db.Save(taskModel)
		BadRequest(c, taskModel.ErrorMessage)
		return
	}

	// Submit the batch engine task (engine task ID == taskModel ID, so the
	// existing completion callback marks this task done when it finishes).
	coreTask := core.Task{
		ID:         taskID,
		Name:       req.Name,
		UserID:     userID,
		Protocol:   "batch",
		Batch:      req.Batch,
		OutputMode: outputMode,
		Interface:  iface,
		PcapFile:   pcapFile,
	}
	if dualPort && req.OutputConfig != nil {
		coreTask.Interface2 = req.OutputConfig.Interface2
	}
	if err := h.engine.SubmitTask(coreTask); err != nil {
		h.engine.UnregisterOutputWriter(taskID)
		taskModel.Status = "error"
		taskModel.ErrorMessage = err.Error()
		h.db.Save(taskModel)
		BadRequest(c, err.Error())
		return
	}

	Created(c, map[string]string{"id": taskID})
}

// List lists all tasks for the current user with server-side pagination.
func (h *TaskHandler) List(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	// Parse query parameters
	page := 1
	size := 20
	if p, err := strconv.Atoi(c.DefaultQuery("page", "1")); err == nil && p > 0 {
		page = p
	}
	if s, err := strconv.Atoi(c.DefaultQuery("size", "20")); err == nil && s > 0 {
		size = s
		if size > 100 {
			size = 100
		}
	}

	// Build query
	query := h.db.Model(&storage.TaskModel{}).Where("user_id = ?", userID)

	// Status filter
	if statusFilter := c.Query("status"); statusFilter != "" {
		query = query.Where("status = ?", statusFilter)
	}

	// Count total
	var total int64
	query.Count(&total)

	// Sorting
	sortBy := c.DefaultQuery("sort_by", "created_at")
	sortOrder := c.DefaultQuery("sort_order", "descending")
	allowedSortColumns := map[string]bool{"created_at": true, "updated_at": true, "name": true, "status": true, "progress": true}
	if !allowedSortColumns[sortBy] {
		sortBy = "created_at"
	}
	orderDir := "DESC"
	if sortOrder == "ascending" {
		orderDir = "ASC"
	}
	query = query.Order(sortBy + " " + orderDir)

	// Pagination
	offset := (page - 1) * size
	query = query.Offset(offset).Limit(size)

	var tasks []storage.TaskModel
	if err := query.Find(&tasks).Error; err != nil {
		InternalError(c, "failed to list tasks: "+err.Error())
		return
	}

	result := make([]TaskResponse, len(tasks))
	for i, t := range tasks {
		result[i] = convertTaskToResponse(&t)
	}

	Success(c, map[string]interface{}{
		"items": result,
		"total": total,
		"page":  page,
		"size":  size,
	})
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

	// Include strategies in the single-task detail response
	Success(c, convertTaskToResponseWithDB(&task, h.db))
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
	if task.Status == "running" || task.Status == "starting" {
		BadRequest(c, "task is already running")
		return
	}

	// Optimistic lock: atomically set status to prevent concurrent starts
	result := h.db.Model(&storage.TaskModel{}).
		Where("id = ? AND status = ?", id, task.Status).
		Update("status", "starting")
	if result.RowsAffected == 0 {
		BadRequest(c, "task status changed, please retry")
		return
	}
	task.Status = "starting"

	// Reset state for re-start
	task.Progress = 0
	task.ErrorMessage = ""
	task.CompletedAt = nil

	// Batch tasks are auto-started on creation and use BatchConfig instead of
	// StrategyIDs. Re-starting them is not supported — the engine task ID format
	// differs (plain taskID vs {taskID}-{strategyID}) and the batch spec is not
	// re-runnable. Return a clear error instead of failing later with the
	// misleading "corrupt strategy_ids" message.
	if task.StrategyIDs == "" && task.BatchConfig != "" {
		task.Status = "error"
		task.ErrorMessage = "batch tasks are auto-started on creation and cannot be restarted"
		h.db.Save(&task)
		BadRequest(c, task.ErrorMessage)
		return
	}

	// Validate all strategies exist and convert to engine tasks
	var strategyIDs []string
	if err := json.Unmarshal([]byte(task.StrategyIDs), &strategyIDs); err != nil {
		task.Status = "error"
		task.ErrorMessage = "corrupt strategy_ids in task record"
		h.db.Save(&task)
		InternalError(c, task.ErrorMessage)
		return
	}

	// Resolve port interface name if needed
	var portGroupIface string
	if task.OutputType == "port_group" {
		var outputConfig OutputConfigRequest
		json.Unmarshal([]byte(task.OutputConfig), &outputConfig)
		if outputConfig.PortGroupID != "" {
			var portGroup storage.PortGroupModel
			if err := h.db.Where("id = ?", outputConfig.PortGroupID).First(&portGroup).Error; err == nil {
				var portsConfig []map[string]interface{}
				json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig)
				if len(portsConfig) > 0 {
					if iface, ok := portsConfig[0]["interface"].(string); ok {
						portGroupIface = iface
					}
				}
			}
		}
	}

	// Load all strategies first for conflict validation
	var loadedStrategies []storage.StrategyModel
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
		loadedStrategies = append(loadedStrategies, strategy)
	}
	// Replay+bps conflict: replay original/multiplier + task bps is forbidden
	var taskFC *FlowControlRequest
	if task.FlowControl != "" {
		taskFC = &FlowControlRequest{}
		json.Unmarshal([]byte(task.FlowControl), taskFC)
	}
	if err := validateReplayBPSConflict(loadedStrategies, taskFC); err != nil {
		task.Status = "error"
		task.ErrorMessage = err.Error()
		h.db.Save(&task)
		BadRequest(c, task.ErrorMessage)
		return
	}

	var coreTasks []*core.Task
	var failedIDs []string
	for _, strategy := range loadedStrategies {
		coreTask, err := core.StrategyModelToTask(&task, &strategy, portGroupIface)
		if err != nil {
			log.Printf("error converting strategy %s: %v", strategy.ID, err)
			failedIDs = append(failedIDs, strategy.ID)
			continue
		}
		coreTasks = append(coreTasks, coreTask)
	}

	if len(coreTasks) == 0 {
		task.Status = "error"
		task.ErrorMessage = "no valid strategies to execute"
		h.db.Save(&task)
		BadRequest(c, task.ErrorMessage)
		return
	}

	// Validate and resolve output paths before proceeding
	if task.OutputType == "pcap" {
		var outputConfig OutputConfigRequest
		json.Unmarshal([]byte(task.OutputConfig), &outputConfig)
		resolved, err := resolvePcapPath(outputConfig.PcapPath)
		if err != nil {
			task.Status = "error"
			task.ErrorMessage = err.Error()
			h.db.Save(&task)
			BadRequest(c, task.ErrorMessage)
			return
		}
		// Update task with resolved path
		outputConfig.PcapPath = resolved
		resolvedJSON, _ := json.Marshal(&outputConfig)
		task.OutputConfig = string(resolvedJSON)
		h.db.Save(&task)

		// Update coreTasks with resolved path
		for i := range coreTasks {
			coreTasks[i].PcapFile = resolved
		}
	}

	// Detect dual-port replay: an explicit interface2 in the output config,
	// OR any loaded replay strategy whose Config has direction="dual".
	// Mirrors CreateBatch's dual-port detection (§16.11). When set, each
	// engine task gets a DualWriter pair: c2s -> primary, s2c -> secondary.
	var outputConfigForDual OutputConfigRequest
	json.Unmarshal([]byte(task.OutputConfig), &outputConfigForDual)
	dualPort := outputConfigForDual.Interface2 != ""
	if !dualPort {
		for _, s := range loadedStrategies {
			if s.Mode != "replay" {
				continue
			}
			var rs struct {
				Direction string `json:"direction"`
			}
			if json.Unmarshal([]byte(s.Config), &rs) == nil && rs.Direction == "dual" {
				dualPort = true
				break
			}
		}
	}
	if dualPort && task.OutputType == "port_group" && outputConfigForDual.Interface2 == "" {
		task.Status = "error"
		task.ErrorMessage = "dual-port replay requires a second interface (interface2 in output_config)"
		h.db.Save(&task)
		BadRequest(c, task.ErrorMessage)
		return
	}

	// Raise NIC MTU if engine.min_mtu is configured. Done after dual-port
	// validation (so we know interface2 is valid) but BEFORE creating output
	// writers / SubmitTask. On failure the task is marked failed -- the
	// operator must either run as root or lower engine.min_mtu.
	if _, err := h.ensureTaskMTU(&task, outputConfigForDual.Interface2); err != nil {
		task.Status = "error"
		task.ErrorMessage = err.Error()
		h.db.Save(&task)
		BadRequest(c, task.ErrorMessage)
		return
	}

	// Set up output writers BEFORE submitting engine tasks to avoid race
	var writerErrors []string
	for _, ct := range coreTasks {
		var writer core.PacketWriter
		var err error

		if ct.OutputMode == "interface" && ct.Interface != "" {
			writer, err = newInterfacePacketWriter(ct.Interface)
		} else if ct.PcapFile != "" {
			writer, err = newPcapPacketWriter(ct.PcapFile)
		}

		if err != nil {
			log.Printf("failed to create output writer for task %s: %v", ct.ID, err)
			writerErrors = append(writerErrors, fmt.Sprintf("%s: %v", ct.ID, err))
			continue
		}

		if dualPort {
			// Create the secondary writer for s2c traffic. Interface mode uses
			// interface2; pcap mode appends ".s2c" to the path. On failure we
			// close the primary writer and record the error so the task fails
			// rather than silently degrading to single-port.
			var writer2 core.PacketWriter
			if ct.OutputMode == "interface" {
				writer2, err = newInterfacePacketWriter(outputConfigForDual.Interface2)
			} else if ct.PcapFile != "" {
				writer2, err = newPcapPacketWriter(ct.PcapFile + ".s2c")
			}
			if err != nil {
				if writer != nil {
					writer.Close()
				}
				log.Printf("failed to create second output writer for task %s: %v", ct.ID, err)
				writerErrors = append(writerErrors, fmt.Sprintf("%s: %v", ct.ID, err))
				continue
			}
			ct.Interface2 = outputConfigForDual.Interface2
			h.engine.RegisterDualWriter(ct.ID, writer, writer2)
		} else if writer != nil {
			h.engine.RegisterOutputWriter(ct.ID, writer)
		}
	}

	// If all output writers failed, mark task as error before submitting
	if len(writerErrors) > 0 && len(writerErrors) == len(coreTasks) {
		task.Status = "error"
		task.ErrorMessage = fmt.Sprintf("failed to create output writers: %v", writerErrors)
		task.Progress = 0
		h.db.Save(&task)
		BadRequest(c, task.ErrorMessage)
		return
	} else if len(writerErrors) > 0 {
		log.Printf("warning: %d/%d output writers failed: %v", len(writerErrors), len(coreTasks), writerErrors)
	}

	// Submit all engine tasks
	var submittedIDs []string
	for _, ct := range coreTasks {
		// Skip tasks whose output writer failed
		skip := false
		for _, we := range writerErrors {
			if len(we) >= len(ct.ID) && we[:len(ct.ID)] == ct.ID {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		if err := h.engine.SubmitTask(*ct); err != nil {
			log.Printf("error submitting engine task %s: %v", ct.ID, err)
			h.engine.UnregisterOutputWriter(ct.ID)
			h.engine.UnregisterDualWriter(ct.ID)
			failedIDs = append(failedIDs, ct.ID)
			continue
		}
		submittedIDs = append(submittedIDs, ct.ID)
	}

	if len(submittedIDs) == 0 {
		task.Status = "error"
		task.ErrorMessage = "failed to start any strategy"
		h.db.Save(&task)
		// Clean up flow-control state created during the failed SubmitTask attempts
		// (parent rate bucket + shared flow counter). Without this, a task that
		// never successfully starts leaks entries in the engine's maps.
		h.engine.CleanupTaskFlowControl(id)
		InternalError(c, task.ErrorMessage)
		return
	}

	task.Status = "running"
	now := currentTime()
	task.StartedAt = &now
	h.db.Save(&task)

	// Reserve ports for port_group output
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
						Where("name = ? AND (status = ? OR current_task_id = ?)", iface, "idle", "").
						Updates(map[string]interface{}{
							"status":          "using",
							"current_task_id": id,
						})
				}
			}
		}
	}

	SuccessWithMessage(c, "task started", map[string]interface{}{
		"engine_task_ids": submittedIDs,
	})
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

	// Update DB status first for consistency
	task.Status = "stopped"
	now := currentTime()
	task.CompletedAt = &now
	h.db.Save(&task)

	// Release port group ports
	h.releasePortGroupPorts(&task)

	// Batch tasks: engine task ID == task ID (no strategy suffix), and
	// StrategyIDs is empty by design. Stop the single engine task directly
	// and clean up both OutputWriter and DualWriter (whichever was registered).
	if task.BatchConfig != "" {
		h.engine.UnregisterOutputWriter(id)
		h.engine.UnregisterDualWriter(id)
		if err := h.engine.StopTask(id); err != nil {
			log.Printf("error stopping batch engine task %s: %v", id, err)
		}
		h.engine.CleanupTaskFlowControl(id)
		SuccessWithMessage(c, "task stopped", map[string]interface{}{
			"stopped_engine_tasks": []string{id},
		})
		return
	}

	// Stop engine tasks and unregister output writers (best-effort after DB update)
	var strategyIDs []string
	if err := json.Unmarshal([]byte(task.StrategyIDs), &strategyIDs); err != nil {
		log.Printf("corrupt strategy_ids for task %s: %v", id, err)
		SuccessWithMessage(c, "task stopped (engine cleanup may be incomplete)", nil)
		return
	}
	var stopped []string
	for _, strategyID := range strategyIDs {
		engineTaskID := fmt.Sprintf("%s-%s", id, strategyID)
		h.engine.UnregisterOutputWriter(engineTaskID)
		h.engine.UnregisterDualWriter(engineTaskID)
		if err := h.engine.StopTask(engineTaskID); err != nil {
			log.Printf("error stopping engine task %s: %v", engineTaskID, err)
			continue
		}
		stopped = append(stopped, engineTaskID)
	}

	// Clean up task-level flow control state (parent bucket + flow counter).
	h.engine.CleanupTaskFlowControl(id)

	SuccessWithMessage(c, "task stopped", map[string]interface{}{
		"stopped_engine_tasks": stopped,
	})
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

// History returns completed task history.
func (h *TaskHandler) History(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	// Parse query parameters
	page := 1
	size := 20
	if p, err := strconv.Atoi(c.DefaultQuery("page", "1")); err == nil && p > 0 {
		page = p
	}
	if s, err := strconv.Atoi(c.DefaultQuery("size", "20")); err == nil && s > 0 {
		size = s
		if size > 100 {
			size = 100
		}
	}

	// Build query
	query := h.db.Model(&storage.TaskModel{}).Where("user_id = ? AND status IN ?", userID, []string{"completed", "failed", "stopped", "error"})

	// Time range filter
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if startTime, err := strconv.ParseInt(startTimeStr, 10, 64); err == nil {
			query = query.Where("created_at >= ?", time.Unix(startTime, 0))
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if endTime, err := strconv.ParseInt(endTimeStr, 10, 64); err == nil {
			query = query.Where("created_at <= ?", time.Unix(endTime, 0))
		}
	}

	// Status filter
	if statusFilter := c.Query("status"); statusFilter != "" {
		query = query.Where("status = ?", statusFilter)
	}

	// Count total
	var total int64
	query.Count(&total)

	// Sorting
	sortBy := c.DefaultQuery("sort_by", "created_at")
	sortOrder := c.DefaultQuery("sort_order", "descending")
	allowedSortColumns := map[string]bool{"created_at": true, "updated_at": true, "name": true, "status": true, "progress": true}
	if !allowedSortColumns[sortBy] {
		sortBy = "created_at"
	}
	orderDir := "DESC"
	if sortOrder == "ascending" {
		orderDir = "ASC"
	}
	query = query.Order(sortBy + " " + orderDir)

	// Pagination
	offset := (page - 1) * size
	query = query.Offset(offset).Limit(size)

	var tasks []storage.TaskModel
	if err := query.Find(&tasks).Error; err != nil {
		InternalError(c, "failed to list history: "+err.Error())
		return
	}

	result := make([]TaskResponse, len(tasks))
	for i, t := range tasks {
		result[i] = convertTaskToResponse(&t)
	}

	Success(c, map[string]interface{}{
		"items": result,
		"total": total,
		"page":  page,
		"size":  size,
	})
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
		Protocol:     t.Protocol,
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

// convertTaskToResponseWithDB converts a TaskModel to TaskResponse with DB access for strategies.
func convertTaskToResponseWithDB(t *storage.TaskModel, db *storage.DB) TaskResponse {
	resp := convertTaskToResponse(t)

	// Populate strategies
	var strategyIDs []string
	json.Unmarshal([]byte(t.StrategyIDs), &strategyIDs)

	if len(strategyIDs) > 0 {
		var strategies []storage.StrategyModel
		db.Where("id IN ?", strategyIDs).Find(&strategies)

		stratMap := make(map[string]storage.StrategyModel)
		for _, s := range strategies {
			stratMap[s.ID] = s
		}

		for _, sid := range strategyIDs {
			if s, ok := stratMap[sid]; ok {
				var fc *FlowControlRequest
				if s.FlowControl != "" {
					fc = &FlowControlRequest{}
					json.Unmarshal([]byte(s.FlowControl), fc)
				}
				resp.Strategies = append(resp.Strategies, StrategyBrief{
					ID:          s.ID,
					Name:        s.Name,
					Mode:        s.Mode,
					Protocol:    s.Protocol,
					FlowControl: fc,
				})
			}
		}
	}

	return resp
}

// calculateTaskHash calculates a hash for task configuration.
func calculateTaskHash(strategyIDs []string, outputConfig string) string {
	data := ""
	for _, id := range strategyIDs {
		data += id
	}
	data += outputConfig
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// validateReplayBPSConflict checks that no replay strategy with original or
// multiplier speed coexists with bps task-level flow control. The R-F2 invariant
// forbids a TimestampPacer (used by original/multiplier) from sharing a packet
// with the engine's parent bps bucket — so if the task ceiling is bps, every
// replay strategy must use bps speed mode (engine child bucket, no _pacer).
func validateReplayBPSConflict(strategies []storage.StrategyModel, taskFC *FlowControlRequest) error {
	if taskFC == nil || taskFC.Type != "bps" {
		return nil
	}
	for _, s := range strategies {
		if s.Mode == "replay" {
			var rs struct {
				Speed struct {
					Mode string `json:"mode"`
				} `json:"speed"`
			}
			if json.Unmarshal([]byte(s.Config), &rs) == nil && (rs.Speed.Mode == "original" || rs.Speed.Mode == "multiplier") {
				return fmt.Errorf("replay strategy %q has %s speed limit, cannot combine with bps task-level flow control", s.Name, rs.Speed.Mode)
			}
		}
	}
	return nil
}

// currentTime returns current time (helper for testing).
func currentTime() time.Time {
	return time.Now()
}

// resolvePcapPath validates and resolves a PCAP path.
// Relative paths are prepended with "pcap/" directory.
// Parent directories are auto-created if they don't exist.
func resolvePcapPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("pcap_path is required")
	}
	// Reject Windows-style absolute paths
	if len(path) >= 2 && path[1] == ':' && (path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z') {
		return "", fmt.Errorf("invalid pcap_path: Windows-style path \"%s\" is not supported on this system", path)
	}
	// Reject UNC paths
	if len(path) >= 2 && path[0] == '\\' && path[1] == '\\' {
		return "", fmt.Errorf("invalid pcap_path: UNC path \"%s\" is not supported on this system", path)
	}
	// Relative paths go under pcap/ directory
	if !filepath.IsAbs(path) && !strings.HasPrefix(path, "pcap/") && !strings.HasPrefix(path, "pcap\\") {
		path = filepath.Join("pcap", path)
	}
	// Auto-create parent directory
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory \"%s\": %w", dir, err)
	}
	return path, nil
}

// pcapPacketWriter adapts output.PCAPWriter to core.PacketWriter.
type pcapPacketWriter struct {
	w *output.PCAPWriter
}

func (pw *pcapPacketWriter) WritePackets(packets [][]byte) error {
	return pw.w.Write(packets)
}

// WriteTimedPackets implements core.TimedWriter so the pcap output uses the
// scheduled send timestamp (§12) instead of time.Now(). The OutputWorker
// prefers this path over WritePackets when present.
func (pw *pcapPacketWriter) WriteTimedPackets(packets []core.PacketOutput) error {
	tp := make([]output.TimedPacket, len(packets))
	for i, p := range packets {
		tp[i] = output.TimedPacket{Data: p.Data, Timestamp: p.Timestamp}
	}
	return pw.w.WriteTimed(tp)
}

func (pw *pcapPacketWriter) Close() error {
	return pw.w.Close()
}

// interfacePacketWriter adapts output.InterfaceWriter to core.PacketWriter.
type interfacePacketWriter struct {
	w *output.InterfaceWriter
}

func (iw *interfacePacketWriter) WritePackets(packets [][]byte) error {
	return iw.w.Write(packets)
}

func (iw *interfacePacketWriter) Close() error {
	return iw.w.Close()
}

func newPcapPacketWriter(path string) (core.PacketWriter, error) {
	w, err := output.NewPCAPWriter(path)
	if err != nil {
		return nil, err
	}
	return &pcapPacketWriter{w: w}, nil
}

func newInterfacePacketWriter(iface string) (core.PacketWriter, error) {
	w, err := output.NewInterfaceWriter(iface)
	if err != nil {
		return nil, err
	}
	return &interfacePacketWriter{w: w}, nil
}
