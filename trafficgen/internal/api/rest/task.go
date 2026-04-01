package rest

import (
	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
)

// TaskHandler handles task-related requests.
type TaskHandler struct {
	engine *core.Engine
}

// NewTaskHandler creates a new task handler.
func NewTaskHandler(engine *core.Engine) *TaskHandler {
	return &TaskHandler{engine: engine}
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

	// Submit task
	if err := h.engine.SubmitTask(task); err != nil {
		InternalError(c, "failed to submit task: "+err.Error())
		return
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

	// TODO: Implement actual task listing from storage
	// For now, return empty list
	Success(c, ListTasksResponse{
		Tasks: []TaskResponse{},
		Total: 0,
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

	// TODO: Implement task start logic
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

	// TODO: Implement task stop logic
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

	// TODO: Implement task deletion from storage
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
