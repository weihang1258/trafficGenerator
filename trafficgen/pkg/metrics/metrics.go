// Package metrics provides Prometheus metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics.
var (
	// PacketsSent counts total packets sent.
	PacketsSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "trafficgen_packets_sent_total",
		Help: "Total number of packets sent",
	}, []string{"protocol", "interface"})

	// BytesSent counts total bytes sent.
	BytesSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "trafficgen_bytes_sent_total",
		Help: "Total number of bytes sent",
	}, []string{"protocol", "interface"})

	// PacketsDropped counts packets dropped.
	PacketsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "trafficgen_packets_dropped_total",
		Help: "Total number of packets dropped",
	}, []string{"reason"})

	// FlowsCreated counts flows created.
	FlowsCreated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "trafficgen_flows_created_total",
		Help: "Total number of flows created",
	}, []string{"protocol"})

	// FlowsCompleted counts flows completed.
	FlowsCompleted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "trafficgen_flows_completed_total",
		Help: "Total number of flows completed",
	}, []string{"protocol", "status"})

	// ActiveTasks tracks active tasks.
	ActiveTasks = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "trafficgen_active_tasks",
		Help: "Number of active tasks",
	})

	// ActiveFlows tracks active flows.
	ActiveFlows = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "trafficgen_active_flows",
		Help: "Number of active flows",
	})

	// BufferUsage tracks buffer usage.
	BufferUsage = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "trafficgen_buffer_usage",
		Help: "Buffer usage percentage",
	}, []string{"buffer"})

	// BufferSize tracks buffer size.
	BufferSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "trafficgen_buffer_size",
		Help: "Buffer size in packets",
	}, []string{"buffer"})

	// TaskDuration tracks task duration.
	TaskDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "trafficgen_task_duration_seconds",
		Help:    "Task duration in seconds",
		Buckets: prometheus.ExponentialBuckets(1, 2, 15), // 1s to ~9 hours
	}, []string{"protocol"})

	// PacketLatency tracks packet processing latency.
	PacketLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "trafficgen_packet_latency_seconds",
		Help:    "Packet processing latency in seconds",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15), // 0.1ms to ~1.6s
	}, []string{"stage"})

	// WorkerQueueLength tracks worker queue length.
	WorkerQueueLength = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "trafficgen_worker_queue_length",
		Help: "Worker queue length",
	}, []string{"worker_type"})

	// APIRequests counts API requests.
	APIRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "trafficgen_api_requests_total",
		Help: "Total number of API requests",
	}, []string{"method", "path", "status"})

	// APILatency tracks API latency.
	APILatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "trafficgen_api_latency_seconds",
		Help:    "API request latency in seconds",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms to ~16s
	}, []string{"method", "path"})

	// WebSocketConnections tracks WebSocket connections.
	WebSocketConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "trafficgen_websocket_connections",
		Help: "Number of active WebSocket connections",
	})

	// PortAllocations tracks port allocations.
	PortAllocations = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "trafficgen_port_allocations",
		Help: "Number of allocated ports",
	})

	// PortWaitQueue tracks port wait queue.
	PortWaitQueue = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "trafficgen_port_wait_queue",
		Help: "Number of tasks waiting for ports",
	})
)

// RecordPacketSent records a packet sent.
func RecordPacketSent(protocol, iface string, bytes int) {
	PacketsSent.WithLabelValues(protocol, iface).Inc()
	BytesSent.WithLabelValues(protocol, iface).Add(float64(bytes))
}

// RecordPacketDropped records a packet dropped.
func RecordPacketDropped(reason string) {
	PacketsDropped.WithLabelValues(reason).Inc()
}

// RecordFlowCreated records a flow created.
func RecordFlowCreated(protocol string) {
	FlowsCreated.WithLabelValues(protocol).Inc()
	ActiveFlows.Inc()
}

// RecordFlowCompleted records a flow completed.
func RecordFlowCompleted(protocol, status string) {
	FlowsCompleted.WithLabelValues(protocol, status).Inc()
	ActiveFlows.Dec()
}

// RecordTaskDuration records task duration.
func RecordTaskDuration(protocol string, duration float64) {
	TaskDuration.WithLabelValues(protocol).Observe(duration)
}

// RecordPacketLatency records packet latency.
func RecordPacketLatency(stage string, latency float64) {
	PacketLatency.WithLabelValues(stage).Observe(latency)
}

// RecordAPIRequest records an API request.
func RecordAPIRequest(method, path, status string, latency float64) {
	APIRequests.WithLabelValues(method, path, status).Inc()
	APILatency.WithLabelValues(method, path).Observe(latency)
}

// SetBufferUsage sets buffer usage.
func SetBufferUsage(buffer string, usage float64) {
	BufferUsage.WithLabelValues(buffer).Set(usage)
}

// SetBufferSize sets buffer size.
func SetBufferSize(buffer string, size float64) {
	BufferSize.WithLabelValues(buffer).Set(size)
}

// SetWorkerQueueLength sets worker queue length.
func SetWorkerQueueLength(workerType string, length float64) {
	WorkerQueueLength.WithLabelValues(workerType).Set(length)
}

// SetWebSocketConnections sets WebSocket connection count.
func SetWebSocketConnections(count float64) {
	WebSocketConnections.Set(count)
}

// SetPortAllocations sets port allocation count.
func SetPortAllocations(count float64) {
	PortAllocations.Set(count)
}

// SetPortWaitQueue sets port wait queue length.
func SetPortWaitQueue(length float64) {
	PortWaitQueue.Set(length)
}
