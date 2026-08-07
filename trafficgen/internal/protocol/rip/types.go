// Package rip implements the RIP (RFC 1058 / RFC 2453 / RFC 2080) protocol planner.
package rip

// This file re-exports the RIP types from the core package for convenience.
// The canonical type definitions are in core/types.go.

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// Re-export core types for internal use.
type (
	RIPConfig = core.RIPConfig
	RIPRoute  = core.RIPRoute
	RIPAuth   = core.RIPAuth
	RIPRouter = core.RIPRouter
)
