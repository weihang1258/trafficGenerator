package netif

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// PortAllocation represents a port allocation.
type PortAllocation struct {
	Interface   string    `json:"interface"`
	Port        uint16    `json:"port"`
	TaskID      string    `json:"task_id"`
	AllocatedAt time.Time `json:"allocated_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// Scheduler manages port allocations.
type Scheduler struct {
	allocations map[string]*PortAllocation // key: interface:port
	waitQueue   []portRequest
	mu          sync.Mutex
	cond        *sync.Cond
}

type portRequest struct {
	iface    string
	port     uint16
	taskID   string
	response chan *PortAllocation
	err      chan error
	ctx      context.Context
}

// NewScheduler creates a new port scheduler.
func NewScheduler() *Scheduler {
	s := &Scheduler{
		allocations: make(map[string]*PortAllocation),
		waitQueue:   make([]portRequest, 0),
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// AllocatePort allocates a port for a task.
func (s *Scheduler) AllocatePort(iface string, port uint16, taskID string) (*PortAllocation, error) {
	return s.AllocatePortWithContext(context.Background(), iface, port, taskID)
}

// AllocatePortWithContext allocates a port with context support.
func (s *Scheduler) AllocatePortWithContext(ctx context.Context, iface string, port uint16, taskID string) (*PortAllocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.key(iface, port)

	// Check if port is already allocated
	if alloc, exists := s.allocations[key]; exists {
		// Check if allocation has expired
		if !alloc.ExpiresAt.IsZero() && time.Now().After(alloc.ExpiresAt) {
			// Remove expired allocation
			delete(s.allocations, key)
		} else {
			// Port is in use, add to wait queue
			return s.waitForPort(ctx, iface, port, taskID)
		}
	}

	// Allocate the port
	alloc := &PortAllocation{
		Interface:   iface,
		Port:        port,
		TaskID:      taskID,
		AllocatedAt: time.Now(),
	}

	s.allocations[key] = alloc

	zap.L().Debug("port allocated",
		zap.String("interface", iface),
		zap.Uint16("port", port),
		zap.String("task_id", taskID),
	)

	return alloc, nil
}

// waitForPort waits for a port to become available.
func (s *Scheduler) waitForPort(ctx context.Context, iface string, port uint16, taskID string) (*PortAllocation, error) {
	// Create request
	req := portRequest{
		iface:    iface,
		port:     port,
		taskID:   taskID,
		response: make(chan *PortAllocation, 1),
		err:      make(chan error, 1),
		ctx:      ctx,
	}

	// Add to wait queue
	s.waitQueue = append(s.waitQueue, req)

	zap.L().Debug("port in use, added to wait queue",
		zap.String("interface", iface),
		zap.Uint16("port", port),
		zap.String("task_id", taskID),
		zap.Int("queue_length", len(s.waitQueue)),
	)

	// Release lock while waiting
	s.mu.Unlock()
	defer s.mu.Lock()

	// Wait for response or context cancellation
	select {
	case alloc := <-req.response:
		return alloc, nil
	case err := <-req.err:
		return nil, err
	case <-ctx.Done():
		// Remove from queue
		s.removeFromQueue(req)
		return nil, fmt.Errorf("port allocation cancelled: %w", ctx.Err())
	}
}

// ReleasePort releases a port allocation.
func (s *Scheduler) ReleasePort(iface string, port uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.key(iface, port)

	alloc, exists := s.allocations[key]
	if !exists {
		return nil // Already released
	}

	delete(s.allocations, key)

	zap.L().Debug("port released",
		zap.String("interface", iface),
		zap.Uint16("port", port),
		zap.String("task_id", alloc.TaskID),
	)

	// Check wait queue
	s.processWaitQueue()

	return nil
}

// ReleaseByTask releases all ports allocated to a task.
func (s *Scheduler) ReleaseByTask(taskID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for key, alloc := range s.allocations {
		if alloc.TaskID == taskID {
			delete(s.allocations, key)
			count++
		}
	}

	if count > 0 {
		zap.L().Debug("released ports for task",
			zap.String("task_id", taskID),
			zap.Int("count", count),
		)
		s.processWaitQueue()
	}

	return count
}

// processWaitQueue processes pending port requests.
func (s *Scheduler) processWaitQueue() {
	if len(s.waitQueue) == 0 {
		return
	}

	// Process queue
	newQueue := make([]portRequest, 0)
	for _, req := range s.waitQueue {
		key := s.key(req.iface, req.port)

		if _, exists := s.allocations[key]; !exists {
			// Port is now available
			alloc := &PortAllocation{
				Interface:   req.iface,
				Port:        req.port,
				TaskID:      req.taskID,
				AllocatedAt: time.Now(),
			}
			s.allocations[key] = alloc

			select {
			case req.response <- alloc:
			default:
			}
		} else {
			// Keep in queue
			newQueue = append(newQueue, req)
		}
	}
	s.waitQueue = newQueue
}

// removeFromQueue removes a request from the wait queue.
func (s *Scheduler) removeFromQueue(req portRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, r := range s.waitQueue {
		if r == req {
			s.waitQueue = append(s.waitQueue[:i], s.waitQueue[i+1:]...)
			break
		}
	}
}

// IsAllocated checks if a port is allocated.
func (s *Scheduler) IsAllocated(iface string, port uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.key(iface, port)
	alloc, exists := s.allocations[key]
	if !exists {
		return false
	}

	// Check expiration
	if !alloc.ExpiresAt.IsZero() && time.Now().After(alloc.ExpiresAt) {
		delete(s.allocations, key)
		return false
	}

	return true
}

// GetAllocation returns the allocation for a port.
func (s *Scheduler) GetAllocation(iface string, port uint16) (*PortAllocation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.key(iface, port)
	alloc, exists := s.allocations[key]
	return alloc, exists
}

// ListAllocations returns all current allocations.
func (s *Scheduler) ListAllocations() []*PortAllocation {
	s.mu.Lock()
	defer s.mu.Unlock()

	allocs := make([]*PortAllocation, 0, len(s.allocations))
	for _, alloc := range s.allocations {
		allocs = append(allocs, alloc)
	}
	return allocs
}

// SetExpiry sets an expiry time for an allocation.
func (s *Scheduler) SetExpiry(iface string, port uint16, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.key(iface, port)
	alloc, exists := s.allocations[key]
	if !exists {
		return fmt.Errorf("allocation not found")
	}

	alloc.ExpiresAt = expiry
	return nil
}

// StartAutoRelease starts a goroutine to periodically release expired allocations.
func (s *Scheduler) StartAutoRelease(interval time.Duration) chan struct{} {
	stop := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.releaseExpired()
			case <-stop:
				return
			}
		}
	}()

	return stop
}

// releaseExpired releases all expired allocations.
func (s *Scheduler) releaseExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, alloc := range s.allocations {
		if !alloc.ExpiresAt.IsZero() && now.After(alloc.ExpiresAt) {
			delete(s.allocations, key)
			zap.L().Debug("released expired allocation",
				zap.String("interface", alloc.Interface),
				zap.Uint16("port", alloc.Port),
				zap.String("task_id", alloc.TaskID),
			)
		}
	}

	s.processWaitQueue()
}

// key generates a key for the allocations map.
func (s *Scheduler) key(iface string, port uint16) string {
	return fmt.Sprintf("%s:%d", iface, port)
}

// Stats returns scheduler statistics.
func (s *Scheduler) Stats() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	return map[string]interface{}{
		"allocations": len(s.allocations),
		"wait_queue":  len(s.waitQueue),
	}
}
