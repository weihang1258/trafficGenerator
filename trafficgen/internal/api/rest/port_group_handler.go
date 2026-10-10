package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// PortGroupHandler handles port group requests.
type PortGroupHandler struct {
	db *storage.DB
}

// NewPortGroupHandler creates a new port group handler.
func NewPortGroupHandler(db *storage.DB) *PortGroupHandler {
	return &PortGroupHandler{db: db}
}

// PortConfig represents a port configuration.
type PortConfig struct {
	Interface string `json:"interface" binding:"required"` // Port name
	Weight    int    `json:"weight"`                      // Weight for load balancing
}

// CreatePortGroupRequest represents a create port group request.
type CreatePortGroupRequest struct {
	Ports []PortConfig `json:"ports" binding:"required,min=1"`
}

// PortGroupResponse represents a port group response.
type PortGroupResponse struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	PortsConfig []PortConfig  `json:"ports_config"`
	CreatedAt   int64         `json:"created_at"`
	UpdatedAt   int64         `json:"updated_at"`
}

// Create creates a new port group (idempotent).
func (h *PortGroupHandler) Create(c *gin.Context) {
	var req CreatePortGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Validate ports exist as interfaces (soft check - allow any interface name)
	for _, portConfig := range req.Ports {
		if portConfig.Interface == "" {
			BadRequest(c, "interface name is required")
			return
		}
	}

	// Weight default: omitted/zero weight means the default weight 1.
	// Weight is never consumed at runtime (resolvePortGroupIface only takes
	// the first interface) — its only role is group identity — so a silent
	// 0-vs-1 fork would split identical intents into two groups. Normalize
	// here, the single funnel for manual + auto create, so omitted, 0 and 1
	// hash identically; distinct nonzero weights still yield distinct groups.
	for i := range req.Ports {
		if req.Ports[i].Weight <= 0 {
			req.Ports[i].Weight = 1
		}
	}

	// Sort ports by interface name for consistent hashing
	sort.Slice(req.Ports, func(i, j int) bool {
		return req.Ports[i].Interface < req.Ports[j].Interface
	})

	// Serialize ports config
	portsConfigJSON, err := json.Marshal(req.Ports)
	if err != nil {
		BadRequest(c, "invalid ports config format")
		return
	}

	// Generate name from ports config hash
	configHash := calculatePortsConfigHash(string(portsConfigJSON))
	name := fmt.Sprintf("port_group_%s", configHash[:8])

	// Check if port group already exists
	var existingPortGroup storage.PortGroupModel
	if err := h.db.Where("name = ?", name).First(&existingPortGroup).Error; err == nil {
		// Port group exists, return existing ID + the ACTUAL hash-derived
		// name (P2-18: the requested name is never used — silently dropping
		// it while hiding the real name left callers believing they had
		// created a new group under their name).
		Success(c, map[string]string{
			"id":      existingPortGroup.ID,
			"name":    existingPortGroup.Name,
			"message": "port group already exists",
		})
		return
	}

	// Create new port group
	portGroup := &storage.PortGroupModel{
		ID:          uuid.New().String(),
		Name:        name,
		PortsConfig: string(portsConfigJSON),
	}

	if err := h.db.Create(portGroup).Error; err != nil {
		InternalError(c, "failed to create port group: "+err.Error())
		return
	}

	Created(c, map[string]string{
		"id":   portGroup.ID,
		"name": portGroup.Name,
	})
}

// List lists all port groups.
func (h *PortGroupHandler) List(c *gin.Context) {
	var portGroups []storage.PortGroupModel
	if err := h.db.Find(&portGroups).Error; err != nil {
		InternalError(c, "failed to list port groups: "+err.Error())
		return
	}

	result := make([]PortGroupResponse, len(portGroups))
	for i, pg := range portGroups {
		var portsConfig []PortConfig
		json.Unmarshal([]byte(pg.PortsConfig), &portsConfig)

		result[i] = PortGroupResponse{
			ID:          pg.ID,
			Name:        pg.Name,
			PortsConfig: portsConfig,
			CreatedAt:   pg.CreatedAt.Unix(),
			UpdatedAt:   pg.UpdatedAt.Unix(),
		}
	}

	Success(c, result)
}

// Get gets a port group by ID.
func (h *PortGroupHandler) Get(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing port group id")
		return
	}

	var portGroup storage.PortGroupModel
	if err := h.db.Where("id = ?", id).First(&portGroup).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "port group not found")
			return
		}
		InternalError(c, "failed to get port group: "+err.Error())
		return
	}

	var portsConfig []PortConfig
	json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig)

	Success(c, PortGroupResponse{
		ID:          portGroup.ID,
		Name:        portGroup.Name,
		PortsConfig: portsConfig,
		CreatedAt:   portGroup.CreatedAt.Unix(),
		UpdatedAt:   portGroup.UpdatedAt.Unix(),
	})
}

// Delete deletes a port group.
func (h *PortGroupHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing port group id")
		return
	}

	var portGroup storage.PortGroupModel
	if err := h.db.Where("id = ?", id).First(&portGroup).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "port group not found")
			return
		}
		InternalError(c, "failed to get port group: "+err.Error())
		return
	}

	// Check if port group is used by any tasks (JSON exact match)
	var taskCount int64
	h.db.Model(&storage.TaskModel{}).
		Where("output_config LIKE ?", "%\""+id+"\"%").
		Count(&taskCount)
	if taskCount > 0 {
		BadRequest(c, "port group is used by tasks, cannot delete")
		return
	}

	// Delete port group
	if err := h.db.Delete(&portGroup).Error; err != nil {
		InternalError(c, "failed to delete port group: "+err.Error())
		return
	}

	SuccessWithMessage(c, "port group deleted", map[string]interface{}{"id": id, "deleted": true})
}

// calculatePortsConfigHash calculates a hash for ports configuration.
func calculatePortsConfigHash(portsConfig string) string {
	hash := sha256.Sum256([]byte(portsConfig))
	return hex.EncodeToString(hash[:])
}
