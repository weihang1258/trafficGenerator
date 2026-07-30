package core

import (
	"context"
	"hash/maphash"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestProcessTask_SpecValidationErrors_FailsTask verifies that the single-task
// path (worker.go processTask) inspects FlowSpec.ValidationErrors (populated
// by strategy_convert.go lines 478-512 from FileSource.Validate()). Without
// this guard, an invalid file_source spec (e.g. fill.bytes=-1) passes
// protocol-specific Validate() and reaches Plan(), where it either silently
// produces zero-bytes or panics on make([]byte, -n). With the fix, the task
// is reported failed via onTaskDone with the underlying ValidationErrors
// message surfaced through the engine's FailTask path.
//
// Per CLAUDE.md Testing Policy §2 (cover failure paths), §3 (one test per
// code path), and §7 (failing-test-first): this is the regression guard for
// B5.1-B5.10 in /tmp/mcp-pcaps/results/B5.md.
func TestProcessTask_SpecValidationErrors_FailsTask(t *testing.T) {
	stub := &stubProtocolPlanner{packetsPerFlow: 1}
	planners := map[string]ProtocolPlanner{"tcp": stub}

	taskChan := make(chan Task, 1)
	configChan := make(chan PacketConfig, 64)
	var wg sync.WaitGroup
	e := NewEngine(EngineConfig{PacketWorkers: 1, QueueSize: 64})
	e.shardedConfigChan = []chan PacketConfig{configChan}
	e.shardCounts = make([]atomic.Int64, 1)
	e.shardSeed = maphash.MakeSeed()
	worker := NewConfigWorker(0, planners, nil, taskChan, &wg, e)

	var (
		mu       sync.Mutex
		gotErr   error
		gotCount int64
		done     = make(chan struct{}, 1)
	)
	worker.SetOnTaskDone(func(taskID string, err error, count int64) {
		mu.Lock()
		gotErr = err
		gotCount = count
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})

	// Drain configChan so processBatchTask never blocks on send.
	drainDone := make(chan struct{})
	go func() {
		for range configChan {
		}
		close(drainDone)
	}()

	// Build a Task whose Spec already has ValidationErrors populated, mirroring
	// what mapToFlowSpec does for a real user submission. We don't go through
	// the full MCP/StrategyModelToTask pipeline because that's not the unit
	// under test -- the unit is "does worker.go honor ValidationErrors?". A
	// direct construction keeps the test focused and fast.
	spec := FlowSpec{}
	spec.ValidationErrors = []string{"filesystem: Fill.Bytes must not be negative"}

	task := Task{
		ID:       "B5.1",
		Ctx:      context.Background(),
		Protocol: "tcp",
		Spec:     spec,
	}
	worker.processTask(task)

	close(configChan)
	<-drainDone

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onTaskDone not called within 2s")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotErr == nil {
		t.Fatalf("invalid spec (ValidationErrors populated) silently completed: gotCount=%d, gotErr=nil. "+
			"Worker must fail the task when spec.ValidationErrors is non-empty.", gotCount)
	}
	if gotCount != 0 {
		t.Errorf("failed task reported count=%d, want 0 (no packets emitted)", gotCount)
	}
	// The error message must carry the underlying validation message so callers
	// can distinguish "user input error" from a generic plumbing failure.
	if got := gotErr.Error(); !strings.Contains(got, "validation") {
		t.Errorf("error = %q, want message mentioning 'validation'", got)
	}
}

// TestProcessBatchTask_SpecValidationErrors_FailsBatch verifies the batch
// path. Mixed-traffic batches convert each class config through mapToFlowSpec
// inside processBatchTask (worker.go line 560), which populates
// spec.ValidationErrors when the class config has an invalid file_source.
// The batch path must reject the entire task (not just skip+warn the flow),
// mirroring the single-task semantic: an invalid input is a user error and
// the API contract is "task failed", not "task completed with warnings".
//
// This covers B5.6 (FTP.DataChannel), B5.7 (SIP.Media), B5.8 (SCTP.Chunks),
// B5.9 (HTTP), and B5.10 (ICMP) at the batch level. Each protocol-specific
// location is exercised by TestProcessBatchTask_SpecValidationErrors_AllSites
// below.
func TestProcessBatchTask_SpecValidationErrors_FailsBatch(t *testing.T) {
	stub := &stubProtocolPlanner{packetsPerFlow: 1}
	planners := map[string]ProtocolPlanner{"tcp": stub}

	taskChan := make(chan Task, 1)
	configChan := make(chan PacketConfig, 64)
	var wg sync.WaitGroup
	e := NewEngine(EngineConfig{PacketWorkers: 1, QueueSize: 64})
	e.shardedConfigChan = []chan PacketConfig{configChan}
	e.shardCounts = make([]atomic.Int64, 1)
	e.shardSeed = maphash.MakeSeed()
	worker := NewConfigWorker(0, planners, nil, taskChan, &wg, e)

	var (
		mu     sync.Mutex
		gotErr error
		done   = make(chan struct{}, 1)
	)
	worker.SetOnTaskDone(func(taskID string, err error, count int64) {
		mu.Lock()
		gotErr = err
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})

	drainDone := make(chan struct{})
	go func() {
		for range configChan {
		}
		close(drainDone)
	}()

	// Submit a real invalid class config: c.Config includes file_source.fill.bytes=-1.
	// mapToFlowSpec (called at worker.go:560) populates spec.ValidationErrors; the
	// batch path must then fail the task with a non-nil error.
	task := Task{
		ID:  "B5.batch",
		Ctx: context.Background(),
		Batch: &BatchSpec{
			Classes: []TrafficClass{{
				ID:        "c1",
				Type:      "tcp",
				FlowCount: 1,
				Config: map[string]interface{}{
					"src_ip": "10.0.0.1",
					"dst_ip": "20.0.0.1",
					"file_source": map[string]interface{}{
						"fill": map[string]interface{}{
							"byte":  0x41,
							"bytes": -1,
						},
					},
				},
			}},
		},
	}
	worker.processBatchTask(task)

	close(configChan)
	<-drainDone

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onTaskDone not called within 2s")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotErr == nil {
		t.Fatalf("batch with invalid file_source.fill.bytes=-1 silently completed: gotErr=nil. "+
			"processBatchTask must fail the task when any class spec has ValidationErrors.")
	}
	if got := gotErr.Error(); !strings.Contains(got, "validation") {
		t.Errorf("error = %q, want message mentioning 'validation'", got)
	}
}

// TestProcessBatchTask_SpecValidationErrors_AllSites exercises the 5
// protocol-specific locations in strategy_convert.go lines 486-512:
// FTP.DataChannel (B5.6), SIP.Media (B5.7), SCTP.Chunks (B5.8), HTTP
// (B5.9), ICMP (B5.10). Each location independently populates
// spec.ValidationErrors; the worker fix must catch them all.
//
// Per CLAUDE.md Testing Policy §3: "If a method/branch exists, it needs a
// test that exercises it." The five protocol-specific FileSource sites are
// distinct code paths in strategy_convert.go and would have been silently
// accepted before this fix.
func TestProcessBatchTask_SpecValidationErrors_AllSites(t *testing.T) {
	// The set of protocol planners we need to register for the batch types
	// we exercise. Each planner is a stub that always succeeds Validate/Plan
	// (so the only failure source is spec.ValidationErrors, isolating the bug).
	stubAll := map[string]ProtocolPlanner{
		"tcp":  &stubProtocolPlanner{packetsPerFlow: 1},
		"udp":  &stubProtocolPlanner{packetsPerFlow: 1},
		"http": &stubProtocolPlanner{packetsPerFlow: 1},
		"icmp": &stubProtocolPlanner{packetsPerFlow: 1},
		"ftp":  &stubProtocolPlanner{packetsPerFlow: 1},
		"sip":  &stubProtocolPlanner{packetsPerFlow: 1},
		"sctp": &stubProtocolPlanner{packetsPerFlow: 1},
	}

	cases := []struct {
		name   string
		class  TrafficClass
		expect string // substring expected in the failure error message
	}{
		{
			name: "B5.6 FTP.DataChannel",
			class: TrafficClass{
				ID: "c1", Type: "ftp", FlowCount: 1,
				Config: map[string]interface{}{
					"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
					"ftp": map[string]interface{}{
						"data_channel": map[string]interface{}{
							"file_source": map[string]interface{}{
								"fill": map[string]interface{}{"byte": 0x41, "bytes": -1},
							},
						},
					},
				},
			},
			expect: "Fill.Bytes",
		},
		{
			name: "B5.7 SIP.Media",
			class: TrafficClass{
				ID: "c1", Type: "sip", FlowCount: 1,
				Config: map[string]interface{}{
					"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
					"sip": map[string]interface{}{
						"media": map[string]interface{}{
							"file_source": map[string]interface{}{
								"fill": map[string]interface{}{"byte": 0x41, "bytes": -1},
							},
						},
					},
				},
			},
			expect: "Fill.Bytes",
		},
		{
			name: "B5.8 SCTP.Chunks",
			class: TrafficClass{
				ID: "c1", Type: "sctp", FlowCount: 1,
				Config: map[string]interface{}{
					"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
					"sctp": map[string]interface{}{
						"chunks": []interface{}{
							map[string]interface{}{
								"file_source": map[string]interface{}{
									"fill": map[string]interface{}{"byte": 0x41, "bytes": -1},
								},
							},
						},
					},
				},
			},
			expect: "Fill.Bytes",
		},
		{
			name: "B5.9 HTTP",
			class: TrafficClass{
				ID: "c1", Type: "http", FlowCount: 1,
				Config: map[string]interface{}{
					"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
					"http": map[string]interface{}{
						"file_source": map[string]interface{}{
							"fill": map[string]interface{}{"byte": 0x41, "bytes": -1},
						},
					},
				},
			},
			expect: "Fill.Bytes",
		},
		{
			name: "B5.10 ICMP",
			class: TrafficClass{
				ID: "c1", Type: "icmp", FlowCount: 1,
				Config: map[string]interface{}{
					"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
					"icmp": map[string]interface{}{
						"file_source": map[string]interface{}{
							"fill": map[string]interface{}{"byte": 0x41, "bytes": -1},
						},
					},
				},
			},
			expect: "Fill.Bytes",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			taskChan := make(chan Task, 1)
			configChan := make(chan PacketConfig, 64)
			var wg sync.WaitGroup
			e := NewEngine(EngineConfig{PacketWorkers: 1, QueueSize: 64})
			e.shardedConfigChan = []chan PacketConfig{configChan}
			e.shardCounts = make([]atomic.Int64, 1)
			e.shardSeed = maphash.MakeSeed()
			worker := NewConfigWorker(0, stubAll, nil, taskChan, &wg, e)

			var (
				mu     sync.Mutex
				gotErr error
				done   = make(chan struct{}, 1)
			)
			worker.SetOnTaskDone(func(taskID string, err error, count int64) {
				mu.Lock()
				gotErr = err
				mu.Unlock()
				select {
				case done <- struct{}{}:
				default:
				}
			})

			drainDone := make(chan struct{})
			go func() {
				for range configChan {
				}
				close(drainDone)
			}()

			task := Task{
				ID:  tc.name,
				Ctx: context.Background(),
				Batch: &BatchSpec{
					Classes: []TrafficClass{tc.class},
				},
			}
			worker.processBatchTask(task)

			close(configChan)
			<-drainDone

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("onTaskDone not called within 2s")
			}

			mu.Lock()
			defer mu.Unlock()
			if gotErr == nil {
				t.Fatalf("invalid %s spec silently completed: gotErr=nil. processBatchTask must fail.",
					tc.name)
			}
			if got := gotErr.Error(); !strings.Contains(got, tc.expect) {
				t.Errorf("error = %q, want substring %q", got, tc.expect)
			}
		})
	}
}

// TestProcessTask_SpecValidationErrors_CleanSpec_NotFlagged is the regression
// guard for the converse case: a valid spec must NOT trip the new guard and
// must run through the planner normally. Without this, a too-eager check
// would fail every valid task and break baseline traffic generation.
//
// Per CLAUDE.md Testing Policy §5 ("assert observable outcomes, not just
// structure"), this asserts that valid input produces a successful run with
// non-zero packet count, NOT merely that the error field is empty.
func TestProcessTask_SpecValidationErrors_CleanSpec_NotFlagged(t *testing.T) {
	stub := &stubProtocolPlanner{packetsPerFlow: 3}
	planners := map[string]ProtocolPlanner{"tcp": stub}

	taskChan := make(chan Task, 1)
	configChan := make(chan PacketConfig, 64)
	var wg sync.WaitGroup
	e := NewEngine(EngineConfig{PacketWorkers: 1, QueueSize: 64})
	e.shardedConfigChan = []chan PacketConfig{configChan}
	e.shardCounts = make([]atomic.Int64, 1)
	e.shardSeed = maphash.MakeSeed()
	worker := NewConfigWorker(0, planners, nil, taskChan, &wg, e)

	var (
		mu       sync.Mutex
		gotErr   error
		gotCount int64
		done     = make(chan struct{}, 1)
	)
	worker.SetOnTaskDone(func(taskID string, err error, count int64) {
		mu.Lock()
		gotErr = err
		gotCount = count
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})

	drainDone := make(chan struct{})
	go func() {
		for range configChan {
		}
		close(drainDone)
	}()

	// Valid spec: empty ValidationErrors, packet-producing file_source.
	spec := FlowSpec{}
	spec.FileSource = &filesystem.FileSource{} // empty, no validation triggered

	task := Task{
		ID:       "clean",
		Ctx:      context.Background(),
		Protocol: "tcp",
		Spec:     spec,
	}
	worker.processTask(task)

	close(configChan)
	<-drainDone

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onTaskDone not called within 2s")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotErr != nil {
		t.Errorf("valid spec failed: %v (the new ValidationErrors guard is over-eager)", gotErr)
	}
	if gotCount != 3 {
		t.Errorf("gotCount = %d, want 3 (packets emitted by stub)", gotCount)
	}
}
