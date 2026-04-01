// Package protocol provides protocol plugin interfaces and registry.
package protocol

import (
	"context"
	"fmt"
	"sync"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner defines the interface for protocol planners.
type Planner interface {
	// Name returns the protocol name.
	Name() string

	// Plan generates packet configs from a flow spec.
	Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error)

	// Validate validates a flow spec.
	Validate(spec core.FlowSpec) error
}

// Registry manages protocol planners.
type Registry struct {
	mu       sync.RWMutex
	planners map[string]Planner
}

// NewRegistry creates a new protocol registry.
func NewRegistry() *Registry {
	return &Registry{
		planners: make(map[string]Planner),
	}
}

// Register registers a protocol planner.
func (r *Registry) Register(planner Planner) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := planner.Name()
	if _, exists := r.planners[name]; exists {
		return fmt.Errorf("protocol already registered: %s", name)
	}

	r.planners[name] = planner
	return nil
}

// Get retrieves a protocol planner by name.
func (r *Registry) Get(name string) (Planner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	planner, ok := r.planners[name]
	return planner, ok
}

// List returns all registered protocol names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.planners))
	for name := range r.planners {
		names = append(names, name)
	}
	return names
}

// Global registry instance.
var globalRegistry = NewRegistry()

// Register registers a protocol planner in the global registry.
func Register(planner Planner) error {
	return globalRegistry.Register(planner)
}

// Get retrieves a protocol planner from the global registry.
func Get(name string) (Planner, bool) {
	return globalRegistry.Get(name)
}

// List returns all registered protocol names from the global registry.
func List() []string {
	return globalRegistry.List()
}
