package metrics

import (
	"testing"
)

func TestRecordPacketSent(t *testing.T) {
	// This test just verifies the function doesn't panic
	RecordPacketSent("tcp", "eth0", 100)
	RecordPacketSent("udp", "eth0", 50)
}

func TestRecordPacketDropped(t *testing.T) {
	RecordPacketDropped("buffer_full")
	RecordPacketDropped("rate_limit")
}

func TestRecordFlowCreated(t *testing.T) {
	RecordFlowCreated("tcp")
	RecordFlowCreated("udp")
}

func TestRecordFlowCompleted(t *testing.T) {
	RecordFlowCompleted("tcp", "success")
	RecordFlowCompleted("tcp", "failed")
}

func TestRecordTaskDuration(t *testing.T) {
	RecordTaskDuration("tcp", 10.5)
	RecordTaskDuration("udp", 5.2)
}

func TestRecordPacketLatency(t *testing.T) {
	RecordPacketLatency("build", 0.001)
	RecordPacketLatency("output", 0.002)
}

func TestRecordAPIRequest(t *testing.T) {
	RecordAPIRequest("GET", "/api/v1/tasks", "200", 0.05)
	RecordAPIRequest("POST", "/api/v1/tasks", "201", 0.1)
}

func TestSetBufferUsage(t *testing.T) {
	SetBufferUsage("combined", 50.5)
	SetBufferUsage("up", 25.0)
}

func TestSetBufferSize(t *testing.T) {
	SetBufferSize("combined", 4096)
}

func TestSetWorkerQueueLength(t *testing.T) {
	SetWorkerQueueLength("config", 10)
	SetWorkerQueueLength("packet", 20)
}

func TestSetWebSocketConnections(t *testing.T) {
	SetWebSocketConnections(5)
}

func TestSetPortAllocations(t *testing.T) {
	SetPortAllocations(10)
}

func TestSetPortWaitQueue(t *testing.T) {
	SetPortWaitQueue(3)
}
