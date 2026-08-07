package mcp

import (
	"github.com/trafficgen/trafficgen/internal/protocol"
)

func init() {
	_ = protocol.Register(NewPlanner())
}