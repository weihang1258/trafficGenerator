package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// querySystemInput covers the 8 system actions. settings is handled by
// flowb_manage_settings (separate tool). The `interface` field is reserved for
// a future single-interface query; current implementation always lists all.
type querySystemInput struct {
	Action    string `json:"action" jsonschema:"operation: status|protocols|stats|health|ready|interfaces|ports|refresh_interfaces"`
	Interface string `json:"interface,omitempty" jsonschema:"reserved for single-interface query (not yet implemented)"`
}

type querySystemOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerSystemTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_query_system",
			Description: "Query system info: status/protocols/stats/health/ready/interfaces/ports, or refresh_interfaces to rescan NICs.",
			OutputSchema: manageOutputSchema(),
		},
		s.handleQuerySystem,
	)
}

func (s *Server) handleQuerySystem(ctx context.Context, req *mcp.CallToolRequest, in querySystemInput) (*mcp.CallToolResult, querySystemOutput, error) {
	start := time.Now()

	var resp *backendResponse
	var err error

	// status/protocols/stats delegate to rest.SystemHandler (envelope-wrapped).
	// health/ready use c.JSON directly (no envelope) -> callRawHandler captures
	// the raw body. interfaces/ports/refresh_interfaces are inline (no handler).
	switch in.Action {
	case "status", "protocols", "stats":
		h := rest.NewSystemHandler(s.engine)
		h.SetDB(s.db)
		switch in.Action {
		case "status":
			resp, err = s.callHandler(ctx, nil, "", nil, h.GetStatus)
		case "protocols":
			resp, err = s.callHandler(ctx, nil, "", nil, h.GetProtocols)
		case "stats":
			resp, err = s.callHandler(ctx, nil, "", nil, h.GetStats)
		}
	case "health":
		h := rest.NewSystemHandler(s.engine)
		resp, err = s.callRawHandler(ctx, h.HealthCheck)
	case "ready":
		h := rest.NewSystemHandler(s.engine)
		resp, err = s.callRawHandler(ctx, h.ReadyCheck)
	case "interfaces":
		resp, err = s.handleSystemInterfaces(ctx)
	case "ports":
		resp, err = s.handleSystemPorts(ctx)
	case "refresh_interfaces":
		resp, err = s.handleSystemRefreshInterfaces(ctx)
	default:
		s.auditLog(req, "flowb_query_system", time.Since(start), "error", "invalid action")
		return nil, querySystemOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (want status|protocols|stats|health|ready|interfaces|ports|refresh_interfaces)", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		s.auditLog(req, "flowb_query_system", duration, "error", err.Error())
		return nil, querySystemOutput{}, err
	}

	s.auditLog(req, "flowb_query_system", duration, "success", "")
	return nil, querySystemOutput{Action: in.Action, Data: rawData(resp.Data)}, nil
}

// handleSystemInterfaces builds the interface list with optional port
// allocation info. When portSched is nil (e.g., tests), allocations are
// omitted and InUse is always false -- still useful for LLM to discover NICs.
func (s *Server) handleSystemInterfaces(ctx context.Context) (*backendResponse, error) {
	if s.ifaceMgr == nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: "interface manager not initialized",
		}
	}

	inUseMap := make(map[string][]rest.PortAllocationBrief)
	if s.portSched != nil {
		for _, alloc := range s.portSched.ListAllocations() {
			inUseMap[alloc.Interface] = append(inUseMap[alloc.Interface], rest.PortAllocationBrief{
				Port:        alloc.Port,
				TaskID:      alloc.TaskID,
				AllocatedAt: alloc.AllocatedAt.Format(time.RFC3339),
			})
		}
	}

	interfaces := s.ifaceMgr.List()
	result := make([]rest.InterfaceResponse, len(interfaces))
	for i, iface := range interfaces {
		ips := make([]string, len(iface.IPs))
		for j, ip := range iface.IPs {
			ips[j] = ip.String()
		}
		allocs := inUseMap[iface.Name]
		result[i] = rest.InterfaceResponse{
			Name:        iface.Name,
			MAC:         iface.MAC.String(),
			IPs:         ips,
			IsUp:        iface.IsUp,
			LinkUp:      iface.LinkUp,
			MTU:         iface.MTU,
			Description: iface.Description,
			IsVirtual:   iface.IsVirtual,
			InUse:       len(allocs) > 0,
			Allocations: allocs,
		}
	}

	data, _ := json.Marshal(result)
	return &backendResponse{Code: 0, Data: data}, nil
}

// handleSystemPorts lists all ports from the DB.
func (s *Server) handleSystemPorts(ctx context.Context) (*backendResponse, error) {
	var ports []storage.PortModel
	if err := s.db.Find(&ports).Error; err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: "failed to list ports: " + err.Error(),
		}
	}

	result := make([]map[string]interface{}, len(ports))
	for i, port := range ports {
		result[i] = map[string]interface{}{
			"id":              port.ID,
			"name":            port.Name,
			"type":            port.Type,
			"pci_address":     port.PCIAddress,
			"status":          port.Status,
			"current_task_id": port.CurrentTaskID,
			"created_at":      port.CreatedAt.Unix(),
			"updated_at":      port.UpdatedAt.Unix(),
		}
	}

	data, _ := json.Marshal(result)
	return &backendResponse{Code: 0, Data: data}, nil
}

// handleSystemRefreshInterfaces rescans NICs via the interface manager.
func (s *Server) handleSystemRefreshInterfaces(ctx context.Context) (*backendResponse, error) {
	if s.ifaceMgr == nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: "interface manager not initialized",
		}
	}
	if err := s.ifaceMgr.Refresh(); err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: "failed to discover interfaces: " + err.Error(),
		}
	}

	data, _ := json.Marshal(map[string]int{
		"count": len(s.ifaceMgr.List()),
	})
	return &backendResponse{Code: 0, Data: data}, nil
}
