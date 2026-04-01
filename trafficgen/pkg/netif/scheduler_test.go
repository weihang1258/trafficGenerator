package netif

import (
	"context"
	"testing"
	"time"
)

func TestScheduler_AllocatePort(t *testing.T) {
	sched := NewScheduler()

	// Allocate port
	alloc, err := sched.AllocatePort("eth0", 8080, "task-1")
	if err != nil {
		t.Fatalf("AllocatePort failed: %v", err)
	}

	if alloc.Interface != "eth0" {
		t.Errorf("Interface = %s, want eth0", alloc.Interface)
	}
	if alloc.Port != 8080 {
		t.Errorf("Port = %d, want 8080", alloc.Port)
	}
	if alloc.TaskID != "task-1" {
		t.Errorf("TaskID = %s, want task-1", alloc.TaskID)
	}
}

func TestScheduler_PortConflict(t *testing.T) {
	sched := NewScheduler()

	// Allocate port
	_, err := sched.AllocatePort("eth0", 8080, "task-1")
	if err != nil {
		t.Fatalf("First allocation failed: %v", err)
	}

	// Try to allocate same port (should go to wait queue)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = sched.AllocatePortWithContext(ctx, "eth0", 8080, "task-2")
	if err == nil {
		t.Error("Should fail with timeout when port is in use")
	}
}

func TestScheduler_ReleasePort(t *testing.T) {
	sched := NewScheduler()

	// Allocate port
	_, err := sched.AllocatePort("eth0", 8080, "task-1")
	if err != nil {
		t.Fatalf("AllocatePort failed: %v", err)
	}

	// Check allocation exists
	if !sched.IsAllocated("eth0", 8080) {
		t.Error("Port should be allocated")
	}

	// Release port
	if err := sched.ReleasePort("eth0", 8080); err != nil {
		t.Fatalf("ReleasePort failed: %v", err)
	}

	// Check allocation removed
	if sched.IsAllocated("eth0", 8080) {
		t.Error("Port should not be allocated after release")
	}
}

func TestScheduler_ReleaseByTask(t *testing.T) {
	sched := NewScheduler()

	// Allocate multiple ports for same task
	sched.AllocatePort("eth0", 8080, "task-1")
	sched.AllocatePort("eth0", 8081, "task-1")
	sched.AllocatePort("eth0", 8082, "task-1")

	// Check allocations
	if len(sched.ListAllocations()) != 3 {
		t.Errorf("Allocations = %d, want 3", len(sched.ListAllocations()))
	}

	// Release all by task
	count := sched.ReleaseByTask("task-1")
	if count != 3 {
		t.Errorf("Released = %d, want 3", count)
	}

	// Check all removed
	if len(sched.ListAllocations()) != 0 {
		t.Errorf("Allocations after release = %d, want 0", len(sched.ListAllocations()))
	}
}

func TestScheduler_Expiry(t *testing.T) {
	sched := NewScheduler()

	// Allocate port
	alloc, _ := sched.AllocatePort("eth0", 8080, "task-1")

	// Set expiry in the past
	sched.SetExpiry("eth0", 8080, time.Now().Add(-time.Hour))

	// Release expired
	sched.releaseExpired()

	// Check removed
	if sched.IsAllocated("eth0", 8080) {
		t.Error("Expired allocation should be removed")
	}
}

func TestScheduler_Stats(t *testing.T) {
	sched := NewScheduler()

	// Initial stats
	stats := sched.Stats()
	if stats["allocations"].(int) != 0 {
		t.Error("Initial allocations should be 0")
	}

	// Allocate ports
	sched.AllocatePort("eth0", 8080, "task-1")
	sched.AllocatePort("eth0", 8081, "task-2")

	// Check stats
	stats = sched.Stats()
	if stats["allocations"].(int) != 2 {
		t.Errorf("Allocations = %d, want 2", stats["allocations"])
	}
}
