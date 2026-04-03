package rest

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"go.uber.org/zap"
)

// TaskHandler handles task-related requests.
type TaskHandler struct {
	engine   *core.Engine
	taskRepo *storage.TaskRepository
}

// NewTaskHandler creates a new task handler.
func NewTaskHandler(engine *core.Engine, taskRepo *storage.TaskRepository) *TaskHandler {
	return &TaskHandler{
		engine:   engine,
		taskRepo: taskRepo,
	}
}

// Create creates a new task.
// POST /api/v1/tasks
func (h *TaskHandler) Create(c *gin.Context) {
	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Create task
	task := core.APIRequestToTask(req.Name, req.Description, req.Protocol, req.Spec, req.Interface)
	task.OutputMode = req.OutputMode
	task.PcapFile = req.PcapFile

	// Submit task to engine
	if err := h.engine.SubmitTask(task); err != nil {
		InternalError(c, "failed to submit task: "+err.Error())
		return
	}

	// Persist to database
	specJSON, _ := json.Marshal(req.Spec)
	taskModel := &storage.TaskModel{
		ID:          task.ID,
		Name:        req.Name,
		Description: req.Description,
		Protocol:    req.Protocol,
		Spec:        string(specJSON),
		Status:      "running",
		Progress:    0,
		CreatedAt:   time.Now(),
	}
	if err := h.taskRepo.Create(taskModel); err != nil {
		zap.L().Error("failed to persist task to database", zap.Error(err))
		// Don't fail the request, task is already running in engine
	}

	Created(c, CreateTaskResponse{
		TaskID:  task.ID,
		Message: "task created successfully",
	})
}

// Get retrieves a task by ID.
// GET /api/v1/tasks/:id
func (h *TaskHandler) Get(c *gin.Context) {
	taskID := c.Param("id")

	status, err := h.engine.GetTaskStatus(taskID)
	if err != nil {
		NotFound(c, "task not found")
		return
	}

	Success(c, TaskResponse{
		ID:          taskID,
		Status:      status.Status,
		Progress:    status.Progress,
		Stats:       status.Stats,
		CreatedAt:   status.CreatedAt.Unix(),
		StartedAt:   status.StartedAt.Unix(),
		CompletedAt: status.CompletedAt.Unix(),
		Error:       status.Error,
	})
}

// List lists all tasks.
// GET /api/v1/tasks
func (h *TaskHandler) List(c *gin.Context) {
	var req ListTasksRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Set defaults
	if req.Page == 0 {
		req.Page = 1
	}
	if req.Size == 0 {
		req.Size = 20
	}

	// Query from database
	tasks, total, err := h.taskRepo.List(req.Page, req.Size, req.Status, req.Protocol)
	if err != nil {
		InternalError(c, "failed to list tasks: "+err.Error())
		return
	}

	// Convert to response format and enrich with real-time status from engine
	responses := make([]TaskResponse, len(tasks))
	for i, task := range tasks {
		responses[i] = TaskResponse{
			ID:          task.ID,
			Name:        task.Name,
			Description: task.Description,
			Protocol:    task.Protocol,
			Status:      task.Status,
			Progress:    task.Progress,
			CreatedAt:   task.CreatedAt.Unix(),
		}

		// Try to get real-time status from engine
		if status, err := h.engine.GetTaskStatus(task.ID); err == nil {
			responses[i].Status = status.Status
			responses[i].Progress = status.Progress
			responses[i].Stats = status.Stats
			if !status.StartedAt.IsZero() {
				responses[i].StartedAt = status.StartedAt.Unix()
			}
			if !status.CompletedAt.IsZero() {
				responses[i].CompletedAt = status.CompletedAt.Unix()
			}
			responses[i].Error = status.Error
		}
	}

	Success(c, ListTasksResponse{
		Tasks: responses,
		Total: int(total),
		Page:  req.Page,
		Size:  req.Size,
	})
}

// Start starts a task.
// POST /api/v1/tasks/:id/start
func (h *TaskHandler) Start(c *gin.Context) {
	taskID := c.Param("id")

	status, err := h.engine.GetTaskStatus(taskID)
	if err != nil {
		NotFound(c, "task not found")
		return
	}

	if status.Status == "running" {
		Conflict(c, "task is already running")
		return
	}

	// Update engine status
	status.Status = "running"
	status.StartedAt = time.Now()

	// Update database
	taskModel, err := h.taskRepo.Get(taskID)
	if err == nil {
		taskModel.Status = "running"
		if err := h.taskRepo.Update(taskModel); err != nil {
			zap.L().Error("failed to update task in database", zap.Error(err))
		}
	}

	SuccessWithMessage(c, "task started", nil)
}

// Stop stops a task.
// POST /api/v1/tasks/:id/stop
func (h *TaskHandler) Stop(c *gin.Context) {
	taskID := c.Param("id")

	status, err := h.engine.GetTaskStatus(taskID)
	if err != nil {
		NotFound(c, "task not found")
		return
	}

	if status.Status != "running" {
		Conflict(c, "task is not running")
		return
	}

	// Update engine status
	status.Status = "stopped"
	status.CompletedAt = time.Now()

	// Update database
	taskModel, err := h.taskRepo.Get(taskID)
	if err == nil {
		taskModel.Status = "stopped"
		taskModel.Progress = status.Progress
		if err := h.taskRepo.Update(taskModel); err != nil {
			zap.L().Error("failed to update task in database", zap.Error(err))
		}
	}

	SuccessWithMessage(c, "task stopped", nil)
}

// Delete deletes a task.
// DELETE /api/v1/tasks/:id
func (h *TaskHandler) Delete(c *gin.Context) {
	taskID := c.Param("id")

	_, err := h.engine.GetTaskStatus(taskID)
	if err != nil {
		NotFound(c, "task not found")
		return
	}

	// Delete from database
	if err := h.taskRepo.Delete(taskID); err != nil {
		InternalError(c, "failed to delete task: "+err.Error())
		return
	}

	// Remove from engine (access taskStore through a method if needed)
	// Note: This requires adding a RemoveTask method to the engine
	// For now, we'll just delete from database

	SuccessWithMessage(c, "task deleted", nil)
}

// GetPackets retrieves packets from a task.
// GET /api/v1/tasks/:id/packets
func (h *TaskHandler) GetPackets(c *gin.Context) {
	taskID := c.Param("id")

	count := 100
	if c.Query("count") != "" {
		c.Query("count")
	}

	mode := c.DefaultQuery("mode", "combined")

	packets := h.engine.GetPackets(count, mode)

	Success(c, map[string]interface{}{
		"task_id":  taskID,
		"packets":  len(packets),
		"mode":     mode,
	})
}
