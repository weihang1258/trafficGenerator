package mcp

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"
)

// auditLog records an MCP tool invocation. client_id is extracted from the
// MCP initialize request (protocol-provided, zero cost). See §10.3.
//
// Sensitive params (pcap_path contents, config details) are NOT logged here;
// tools that want fine-grained param logging must do so themselves (hashing
// first). Only tool name, client identity, duration, and status are recorded.
func (s *Server) auditLog(req *mcp.CallToolRequest, toolName string, duration time.Duration, status string, errStr string) {
	if !s.config.AuditLog {
		return
	}

	clientID, clientVersion := "", ""
	if req != nil && req.Session != nil {
		if initParams := req.Session.InitializeParams(); initParams != nil && initParams.ClientInfo != nil {
			clientID = initParams.ClientInfo.Name
			clientVersion = initParams.ClientInfo.Version
		}
	}

	fields := []zap.Field{
		zap.String("tool", toolName),
		zap.String("client_id", clientID),
		zap.String("client_version", clientVersion),
		zap.Duration("duration", duration),
		zap.String("status", status),
	}
	if errStr != "" {
		fields = append(fields, zap.String("error", errStr))
	}

	zap.L().Info("mcp tool called", fields...)
}
