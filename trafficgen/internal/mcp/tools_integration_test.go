package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 arp 包 init 注册层生成器+校验器（D-ARP-1）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/arp"
	"github.com/trafficgen/trafficgen/internal/replay"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/netif"
)
// mockMCPPlanner emits one packet per Plan() call and validates any FlowSpec.
// It registers under "tcp" so engine.ValidateTask succeeds.
type mockMCPPlanner struct {
	name string
}

func (m *mockMCPPlanner) Name() string                     { return m.name }
func (m *mockMCPPlanner) Validate(spec core.FlowSpec) error { return nil }
func (m *mockMCPPlanner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	ch := make(chan core.PacketConfig)
	go func() {
		defer close(ch)
		for i := 0; i < spec.Count; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- core.PacketConfig{FlowID: "f1", PacketIndex: uint64(i)}:
			}
		}
	}()
	return ch, nil
}

// slowMCPPlanner emits packets with a delay between each so the task stays in
// "running" state long enough for tests to interact with it (e.g., asserting
// delete-on-running fails). The fast mockMCPPlanner completes small tasks in
// <1ms, making "running" state impossible to catch deterministically.
type slowMCPPlanner struct {
	name  string
	delay time.Duration
}

func (m *slowMCPPlanner) Name() string                      { return m.name }
func (m *slowMCPPlanner) Validate(spec core.FlowSpec) error { return nil }
func (m *slowMCPPlanner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	ch := make(chan core.PacketConfig)
	go func() {
		defer close(ch)
		for i := 0; i < spec.Count; i++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(m.delay):
				ch <- core.PacketConfig{FlowID: "f1", PacketIndex: uint64(i)}
			}
		}
	}()
	return ch, nil
}

// testMCPEnv holds the test fixtures for MCP tool integration tests.
type testMCPEnv struct {
	db   *storage.DB
	eng  *core.Engine
	im   *netif.Manager
	srv  *Server
	tmp  string
	done chan string // engine task completion signal
	dbPath string
}

func setupMCPTest(t *testing.T) *testMCPEnv {
	return setupMCPTestWithPlanner(t, &mockMCPPlanner{name: "tcp"})
}

// setupMCPTestWithPlanner creates a test env with a custom planner registered
// under "tcp". Used by tests that need deterministic task timing (e.g., slow
// planner for "running" state assertions).
func setupMCPTestWithPlanner(t *testing.T, planner core.ProtocolPlanner) *testMCPEnv {
	t.Helper()

	// Create temp SQLite database
	tmp, err := os.MkdirTemp("", "mcp-test-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	dbPath := tmp + "/test.db"

	sdb, err := storage.NewDB(&config.DatabaseConfig{Type: "sqlite", SQLite: config.SQLiteConfig{Path: dbPath}})
	if err != nil {
		os.RemoveAll(tmp)
		t.Fatalf("new db: %v", err)
	}

	// Create a user for the MCP service account
	userID := "svc-user-1"
	sdb.Create(&storage.UserModel{
		ID:           userID,
		Username:     "mcp-test-svc",
		PasswordHash: "test-hash",
		Email:        "mcp@test.local",
		Role:         "user",
		Enabled:      true,
	})

	// Create engine
	eng := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	eng.RegisterPlanner(planner)
	eng.SetBuildFunc(func(c core.PacketConfig) ([]byte, error) {
		return make([]byte, 64), nil
	})
	eng.SetLayerPlannerFactory(layers.BuildLayersPlanner)

	done := make(chan string, 4)
	eng.OnTaskComplete = func(taskID string) {
		done <- taskID
	}
	eng.OnTaskFailed = func(taskID, msg string) {
		done <- taskID
	}

	if err := eng.Start(); err != nil {
		eng.Stop()
		sdb.Close()
		os.RemoveAll(tmp)
		t.Fatalf("engine start: %v", err)
	}

	// Create MCP server
	cfg := &config.MCPConfig{
		Enabled:                true,
		ServiceUserID:          "mcp-test-svc",
		ServiceUserRole:        "user",
		ServiceAccountPassword: "test-pass",
		AuditLog:               false,
		Transports:             config.MCPTransports{Stdio: false},
	}
	srv, err := NewServer(cfg, eng, sdb, netif.NewManager())
	if err != nil {
		eng.Stop()
		sdb.Close()
		os.RemoveAll(tmp)
		t.Fatalf("new mcp server: %v", err)
	}
	// JWT manager is needed by flowb_manage_auth (validate/logout/refresh).
	srv.SetJWTManager(auth.NewJWTManager("test-secret", "test-issuer", 24*time.Hour))

	return &testMCPEnv{
		db:     sdb,
		eng:    eng,
		im:     netif.NewManager(),
		srv:    srv,
		tmp:    tmp,
		done:   done,
		dbPath: dbPath,
	}
}

func (e *testMCPEnv) cleanup() {
	e.eng.Stop()
	e.db.Close()
	os.RemoveAll(e.tmp)
}

// setupMCPTestWithRealBuilder creates a test env that registers the real ARP
// planner (arp.NewPlanner) and uses the production BuildFunc wrapper
// (replay.NewBuildFunc(builder.Build)). Tests that need to verify byte-exact
// packet output (e.g. Ethernet padding) must use this helper instead of
// setupMCPTest, whose mockMCPPlanner + fake `make([]byte, 64)` BuildFunc
// never invokes Builder.Build and so can't exercise padding logic.
func setupMCPTestWithRealBuilder(t *testing.T) *testMCPEnv {
	t.Helper()

	tmp, err := os.MkdirTemp("", "mcp-real-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	dbPath := tmp + "/test.db"

	sdb, err := storage.NewDB(&config.DatabaseConfig{Type: "sqlite", SQLite: config.SQLiteConfig{Path: dbPath}})
	if err != nil {
		os.RemoveAll(tmp)
		t.Fatalf("new db: %v", err)
	}

	userID := "svc-user-1"
	sdb.Create(&storage.UserModel{
		ID:           userID,
		Username:     "mcp-test-svc",
		PasswordHash: "test-hash",
		Email:        "mcp@test.local",
		Role:         "user",
		Enabled:      true,
	})

	eng := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	eng.RegisterPlanner(layers.NewChainPlanner("arp")) // D-ARP-1 翻转：链 planner（生产同款）
	eng.SetLayerPlannerFactory(layers.BuildLayersPlanner) // 层链配置经工厂（生产 main.go:611 同款）
	eng.SetBuildFunc(replay.NewBuildFunc(core.NewBuilder().Build))

	done := make(chan string, 4)
	eng.OnTaskComplete = func(taskID string) {
		done <- taskID
	}
	eng.OnTaskFailed = func(taskID, msg string) {
		done <- taskID
	}

	if err := eng.Start(); err != nil {
		eng.Stop()
		sdb.Close()
		os.RemoveAll(tmp)
		t.Fatalf("engine start: %v", err)
	}

	cfg := &config.MCPConfig{
		Enabled:                true,
		ServiceUserID:          "mcp-test-svc",
		ServiceUserRole:        "user",
		ServiceAccountPassword: "test-pass",
		AuditLog:               false,
		Transports:             config.MCPTransports{Stdio: false},
	}
	srv, err := NewServer(cfg, eng, sdb, netif.NewManager())
	if err != nil {
		eng.Stop()
		sdb.Close()
		os.RemoveAll(tmp)
		t.Fatalf("new mcp server: %v", err)
	}
	srv.SetJWTManager(auth.NewJWTManager("test-secret", "test-issuer", 24*time.Hour))

	return &testMCPEnv{
		db:     sdb,
		eng:    eng,
		im:     netif.NewManager(),
		srv:    srv,
		tmp:    tmp,
		done:   done,
		dbPath: dbPath,
	}
}

// readPcapFrameLengths opens the pcap at path with pcapgo (pure Go, no
// tcpdump/root) and returns the CaptureLength of each frame. CaptureLength
// is the on-wire frame length the writer stored — exactly what padding tests
// need to verify.
func readPcapFrameLengths(t *testing.T, path string) []int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcapgo.NewReader: %v", err)
	}
	var lengths []int
	for {
		_, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		lengths = append(lengths, ci.CaptureLength)
	}
	return lengths
}

// ---------------------------------------------------------------------------
// §4.1 flowb_manage_strategies — create / list / get / update / delete
// ---------------------------------------------------------------------------

func TestMCP_ManageStrategies_CreateAndList(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Create
	_, out, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "s1",
		Mode:     "synth",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var createData map[string]string
	json.Unmarshal(asRaw(out.Data), &createData)
	sid := createData["id"]
	if sid == "" {
		t.Fatal("create did not return id")
	}

	// List (StrategyHandler.List returns a JSON array directly, not {items:...})
	_, out2, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "list",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listData []map[string]interface{}
	if err := json.Unmarshal(asRaw(out2.Data), &listData); err != nil {
		t.Fatalf("list returned non-array: %s (err: %v)", string(asRaw(out2.Data)), err)
	}
	if len(listData) == 0 {
		t.Fatalf("list returned empty array: %s", string(asRaw(out2.Data)))
	}
	found := false
	for _, s := range listData {
		if s["id"] == sid {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created strategy %s not in list: %s", sid, string(asRaw(out2.Data)))
	}

	// Get
	_, out3, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     sid,
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var getData map[string]interface{}
	json.Unmarshal(asRaw(out3.Data), &getData)
	if getData["id"] != sid {
		t.Fatalf("get returned wrong id: %v", getData["id"])
	}
}

func TestMCP_ManageStrategies_Update(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, _ := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "s2",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	var d map[string]string
	json.Unmarshal(asRaw(out.Data), &d)

	_, _, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "update",
		ID:       d["id"],
		Name:     "s2-updated",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{"dst_port": float64(443)}}}},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	_, out2, _ := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     d["id"],
	})
	var gd map[string]interface{}
	json.Unmarshal(asRaw(out2.Data), &gd)
	if gd["name"] != "s2-updated" {
		t.Fatalf("name not updated: %v", gd["name"])
	}
	// Verify config field actually changed (not just name). The config is stored
	// as a layers chain; tcp.dst_port should be 443.
	cfg, _ := gd["config"].(map[string]interface{})
	arr, _ := cfg["layers"].([]interface{})
	var port float64
	for _, item := range arr {
		if m, ok := item.(map[string]interface{})["tcp"].(map[string]interface{}); ok {
			port, _ = m["dst_port"].(float64)
		}
	}
	if port != 443 {
		t.Fatalf("config layers tcp.dst_port not updated: got %v, want 443 (full config: %v)", port, cfg)
	}
}

func TestMCP_ManageStrategies_Delete(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, _ := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "s3",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	var d map[string]string
	json.Unmarshal(asRaw(out.Data), &d)

	_, _, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "delete",
		ID:     d["id"],
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, _, err = env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     d["id"],
	})
	if err == nil {
		t.Fatal("get deleted strategy should fail")
	}
}

func TestMCP_ManageStrategies_InvalidAction(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

// ---------------------------------------------------------------------------
// §4.2 flowb_manage_tasks — create / list / get / start / stop / delete
// ---------------------------------------------------------------------------

func TestMCP_ManageTasks_CreateAndStart(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// First create a strategy
	_, sout, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "ts1",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	if err != nil {
		t.Fatalf("create strategy: %v", err)
	}
	var sd map[string]string
	json.Unmarshal(asRaw(sout.Data), &sd)

	// Create task
	_, tout, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action:      "create",
		Name:        "task1",
		StrategyIDs: []string{sd["id"]},
		OutputType:  "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/out.pcap",
		},
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	var td map[string]string
	json.Unmarshal(asRaw(tout.Data), &td)
	tid := td["id"]
	if tid == "" {
		t.Fatal("create task did not return id")
	}

	// Start
	_, _, err = env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "start",
		ID:     tid,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// Get task status
	_, gout, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "get",
		ID:     tid,
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var gt map[string]interface{}
	json.Unmarshal(asRaw(gout.Data), &gt)
	status, _ := gt["status"].(string)
	if status != "running" {
		t.Errorf("expected running, got %q", status)
	}

	// Wait for engine to finish
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete")
	}
}

func TestMCP_ManageTasks_List(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Create two tasks
	_, sout, _ := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "list-s1",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	var sd map[string]string
	json.Unmarshal(asRaw(sout.Data), &sd)

	for i := 0; i < 2; i++ {
		env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
			Action:      "create",
			Name:        fmt.Sprintf("list-task-%d", i),
			StrategyIDs: []string{sd["id"]},
			OutputType:  "pcap",
			OutputConfig: &outputConfigInput{
				PcapPath: env.tmp + fmt.Sprintf("/out-%d.pcap", i),
			},
		})
	}

	_, lout, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "list",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// TaskHandler.List returns {items: [...], total, page, size}. Parse items
	// and assert the count matches what we created (not just bytes length).
	var ld struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(asRaw(lout.Data), &ld); err != nil {
		t.Fatalf("list returned unparseable data: %s (err: %v)", string(asRaw(lout.Data)), err)
	}
	if len(ld.Items) != 2 {
		t.Fatalf("expected 2 items, got %d (total=%d): %s", len(ld.Items), ld.Total, string(asRaw(lout.Data)))
	}
	if ld.Total != 2 {
		t.Errorf("expected total=2, got %d", ld.Total)
	}
}

func TestMCP_ManageTasks_StopFailsNonRunning(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, sout, _ := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "stop-s1",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	var sd map[string]string
	json.Unmarshal(asRaw(sout.Data), &sd)

	_, tout, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action:      "create",
		Name:        "pending-task",
		StrategyIDs: []string{sd["id"]},
		OutputType:  "pcap",
		OutputConfig: &outputConfigInput{PcapPath: env.tmp + "/out.pcap"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var td map[string]string
	json.Unmarshal(asRaw(tout.Data), &td)

	// Stop a "pending" task should fail
	_, _, err = env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "stop",
		ID:     td["id"],
	})
	if err == nil {
		t.Fatal("expected error stopping non-running task")
	}
}

func TestMCP_ManageTasks_DeleteFailsRunning(t *testing.T) {
	// Use a slow planner so the task stays in "running" state long enough to
	// deterministically catch it. The fast mockMCPPlanner completes count=3
	// tasks in <1ms, making the old 100ms sleep flaky (task might finish first,
	// then delete succeeds, then the test fails spuriously).
	env := setupMCPTestWithPlanner(t, &slowMCPPlanner{name: "tcp", delay: 50 * time.Millisecond})
	defer env.cleanup()

	_, sout, _ := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "del-s1",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	var sd map[string]string
	json.Unmarshal(asRaw(sout.Data), &sd)

	_, tout, _ := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action:      "create",
		Name:        "del-task",
		StrategyIDs: []string{sd["id"]},
		OutputType:  "pcap",
		OutputConfig: &outputConfigInput{PcapPath: env.tmp + "/out.pcap"},
	})
	var td map[string]string
	json.Unmarshal(asRaw(tout.Data), &td)

	env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "start",
		ID:     td["id"],
	})

	// Poll for "running" status (deterministic, no fixed sleep). With 50ms
	// delay * 100 packets = ~5s of running time, we have plenty of room.
	deadline := time.Now().Add(3 * time.Second)
	running := false
	for time.Now().Before(deadline) {
		_, gout, _ := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
			Action: "get",
			ID:     td["id"],
		})
		var gt map[string]interface{}
		json.Unmarshal(asRaw(gout.Data), &gt)
		if status, _ := gt["status"].(string); status == "running" {
			running = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !running {
		t.Fatal("task never reached running state within 3s")
	}

	// Delete a running task should fail
	_, _, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "delete",
		ID:     td["id"],
	})
	if err == nil {
		t.Fatal("expected error deleting running task")
	}

	// Wait for completion so cleanup doesn't leave a running task
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
	}
}

func TestMCP_ManageTasks_InvalidAction(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "invalid",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// §4.3 flowb_generate_traffic — one-shot workflow
// ---------------------------------------------------------------------------

func TestMCP_GenerateTraffic_HappyPath(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "gen1",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
		StrategyFlowControl: &flowControlInput{Type: "flows", Value: 3},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/gen1.pcap",
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if out.TaskID == "" {
		t.Fatal("missing task_id")
	}
	if out.StrategyID == "" {
		t.Fatal("missing strategy_id")
	}
	if out.Status != "running" {
		t.Fatalf("expected running, got %q", out.Status)
	}

	// Wait for completion
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("generated task did not complete")
	}

	// Verify strategy and task records exist
	_, _, err = env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     out.StrategyID,
	})
	if err != nil {
		t.Fatalf("strategy not found after generate: %v", err)
	}

	_, _, err = env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "get",
		ID:     out.TaskID,
	})
	if err != nil {
		t.Fatalf("task not found after generate: %v", err)
	}
}

func TestMCP_GenerateTraffic_DuplicateIdempotent(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	input := generateTrafficInput{
		TaskName:   "idem",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
		StrategyFlowControl: &flowControlInput{Type: "flows", Value: 3},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/idem.pcap",
		},
	}

	_, out1, err := env.srv.handleGenerateTraffic(context.Background(), nil, input)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if out1.TaskID == "" {
		t.Fatal("first call returned empty task_id")
	}

	// Wait for the first task to complete before making the second call,
	// so Start on the second call isn't blocked by an already-running task.
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("first task did not complete")
	}

	// Second call with identical input: strategy and task creation are
	// idempotent (matched by name+hash), so both IDs must match the first
	// call. Start may succeed (task completed -> restartable) or fail
	// (still running), but the IDs are the key assertion.
	_, out2, err2 := env.srv.handleGenerateTraffic(context.Background(), nil, input)
	if out2.StrategyID != out1.StrategyID {
		t.Errorf("strategy id mismatch: out1=%s out2=%s (idempotent hit should return same id)",
			out1.StrategyID, out2.StrategyID)
	}
	if out2.TaskID != out1.TaskID {
		t.Errorf("task id mismatch: out1=%s out2=%s (idempotent hit should return same id)",
			out1.TaskID, out2.TaskID)
	}
	if err2 != nil {
		// Start failure: status should be "created" (workflow returns task_id
		// for LLM recovery), not empty.
		if out2.Status != "created" {
			t.Errorf("on Start failure, expected status=created, got %q (err=%v)", out2.Status, err2)
		}
	} else {
		if out2.Status != "running" {
			t.Errorf("on success, expected status=running, got %q", out2.Status)
		}
		// Drain the second task's completion signal.
		select {
		case <-env.done:
		case <-time.After(10 * time.Second):
		}
	}
}

// ---------------------------------------------------------------------------
// §8.1 Error mapping — backend errors mapped to jsonrpc.Error
// ---------------------------------------------------------------------------

func TestMCP_ErrorMapping_NotFound(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     "nonexistent-id",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent strategy")
	}
}

func TestMCP_ErrorMapping_MissingName(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// The REST handler requires "name", so creating without it should 400
	_, _, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

// ---------------------------------------------------------------------------
// Concurrency: multiple generate calls run concurrently
// ---------------------------------------------------------------------------

func TestMCP_ConcurrentGenerate(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	var wg sync.WaitGroup
	results := make(chan generateTrafficOutput, 3)
	errs := make(chan error, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Distinct task names per goroutine -- the old test used the same
			// name "conc" for all 3, so idempotent matching returned the same
			// task_id for all, defeating the purpose of the concurrency test.
			_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
				TaskName:   fmt.Sprintf("conc-%d", idx),
				Protocol:   "tcp",
				Config:     map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{"dst_port": float64(80 + idx)}}}},
				OutputType: "pcap",
				OutputConfig: &outputConfigInput{
					PcapPath: env.tmp + fmt.Sprintf("/conc-%d.pcap", idx),
				},
			})
			if err != nil {
				errs <- err
				return
			}
			results <- out
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)

	for e := range errs {
		t.Errorf("concurrent generate error: %v", e)
	}

	// Collect all task IDs and verify they're non-empty AND distinct.
	// The old test silently ignored empty TaskIDs (sent nil as sentinel),
	// which masked failures where the workflow returned empty output.
	seen := make(map[string]bool)
	count := 0
	for out := range results {
		count++
		if out.TaskID == "" {
			t.Error("concurrent generate returned empty task_id")
			continue
		}
		if seen[out.TaskID] {
			t.Errorf("duplicate task_id across concurrent calls: %s", out.TaskID)
		}
		seen[out.TaskID] = true
	}
	if count != 3 {
		t.Errorf("expected 3 successful results, got %d", count)
	}

	// Drain completion signals for all tasks so cleanup is clean.
	for i := 0; i < count; i++ {
		select {
		case <-env.done:
		case <-time.After(10 * time.Second):
		}
	}
}

// ---------------------------------------------------------------------------
// Spec coverage: list_tasks, create_batch, history, side effects, flow_control
// ---------------------------------------------------------------------------

// TestMCP_ManageStrategies_ListTasks verifies the list_tasks action returns
// tasks linked to a strategy via strategy_ids JSON array.
func TestMCP_ManageStrategies_ListTasks(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, sout, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "lt-s1",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	if err != nil {
		t.Fatalf("create strategy: %v", err)
	}
	var sd map[string]string
	json.Unmarshal(asRaw(sout.Data), &sd)

	// Create two tasks referencing this strategy.
	for i := 0; i < 2; i++ {
		env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
			Action:      "create",
			Name:        fmt.Sprintf("lt-task-%d", i),
			StrategyIDs: []string{sd["id"]},
			OutputType:  "pcap",
			OutputConfig: &outputConfigInput{
				PcapPath: env.tmp + fmt.Sprintf("/lt-%d.pcap", i),
			},
		})
	}

	_, out, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "list_tasks",
		ID:     sd["id"],
	})
	if err != nil {
		t.Fatalf("list_tasks: %v", err)
	}
	// ListTasks returns []TaskBrief{ID, Name, Status}.
	var tasks []map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &tasks); err != nil {
		t.Fatalf("list_tasks returned non-array: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	if len(tasks) != 2 {
		t.Fatalf("expected 2 tasks linked to strategy, got %d: %s", len(tasks), string(asRaw(out.Data)))
	}
	for _, tk := range tasks {
		if tk["id"] == nil || tk["name"] == nil {
			t.Errorf("task missing id/name: %v", tk)
		}
	}
}

// TestMCP_ManageTasks_CreateBatch verifies the create_batch action creates a
// task from an inline BatchSpec (multiple protocol classes) without requiring
// pre-created strategies.
func TestMCP_ManageTasks_CreateBatch(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	batch := map[string]interface{}{
		"classes": []map[string]interface{}{
			{
				"id":              "c1",
				"type":            "tcp",
				"bps":             "1m",
				"flows_per_second": 10,
				"flow_count":      5,
				"tuples": map[string]interface{}{
					"src_ip":   map[string]interface{}{"strategy": "fixed", "value": "10.0.0.1"},
					"dst_ip":   map[string]interface{}{"strategy": "fixed", "value": "10.0.0.2"},
					"src_port": map[string]interface{}{"strategy": "fixed", "value": 1234},
					"dst_port": map[string]interface{}{"strategy": "fixed", "value": 80},
				},
				"config": map[string]interface{}{},
			},
		},
	}

	_, out, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action:     "create_batch",
		Name:       "batch-task",
		Batch:      batch,
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/batch.pcap",
		},
	})
	if err != nil {
		t.Fatalf("create_batch: %v", err)
	}
	var td map[string]string
	json.Unmarshal(asRaw(out.Data), &td)
	if td["id"] == "" {
		t.Fatalf("create_batch did not return id: %s", string(asRaw(out.Data)))
	}

	// Verify the batch task appears in list.
	_, lout, _ := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "list",
	})
	var ld struct {
		Items []map[string]interface{} `json:"items"`
	}
	json.Unmarshal(asRaw(lout.Data), &ld)
	found := false
	for _, item := range ld.Items {
		if item["id"] == td["id"] {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("batch task %s not in task list: %s", td["id"], string(asRaw(lout.Data)))
	}
}

// TestMCP_ManageTasks_History verifies the history action returns tasks
// filtered by time range and status.
func TestMCP_ManageTasks_History(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Generate a task and wait for completion.
	_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "hist-task",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
		StrategyFlowControl: &flowControlInput{Type: "flows", Value: 3},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/hist.pcap",
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete")
	}

	// MCP's TaskHandler is created with registerCallbacks=false (the REST
	// server owns the engine callbacks for DB status updates). In this test
	// there's no REST server, so the DB status stays "running". History
	// filters on terminal statuses (completed/failed/stopped/error), so we
	// manually update the status -- this simulates what the REST callback
	// would do in production.
	env.db.Model(&storage.TaskModel{}).
		Where("id = ?", out.TaskID).
		Updates(map[string]interface{}{
			"status":       "completed",
			"progress":     100,
			"completed_at": time.Now(),
		})

	// Query history with a wide time range covering task creation.
	startTime := time.Now().Add(-1 * time.Hour).Unix()
	endTime := time.Now().Add(1 * time.Hour).Unix()
	_, hout, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action:   "history",
		StartTime: startTime,
		EndTime:   endTime,
	})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var hd struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(asRaw(hout.Data), &hd); err != nil {
		t.Fatalf("history returned unparseable data: %s (err: %v)", string(asRaw(hout.Data)), err)
	}
	if hd.Total == 0 {
		t.Errorf("expected history to contain the completed task, total=0: %s", string(asRaw(hout.Data)))
	}
	found := false
	for _, item := range hd.Items {
		if item["id"] == out.TaskID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("task %s not in history: %s", out.TaskID, string(asRaw(hout.Data)))
	}
}

// TestMCP_GenerateTraffic_PcapSideEffect verifies the pcap file is actually
// written to disk after the task completes -- not just that the task succeeds.
// This catches issues where the output writer is silently skipped.
func TestMCP_GenerateTraffic_PcapSideEffect(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	pcapPath := env.tmp + "/sideeffect.pcap"
	_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "se-task",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
		StrategyFlowControl: &flowControlInput{Type: "flows", Value: 5},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: pcapPath,
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete")
	}

	// In production, the REST server's onEngineTaskComplete callback calls
	// UnregisterOutputWriter, which Close()s the pcap writer and flushes its
	// 256KB bufio buffer. MCP's TaskHandler is created with
	// registerCallbacks=false (REST owns callbacks), so in this test the writer
	// stays unflushed. Manually unregister to simulate the production cleanup
	// and verify packets actually reached the file.
	engineTaskID := out.TaskID + "-" + out.StrategyID
	env.eng.UnregisterOutputWriter(engineTaskID)

	// Assert the pcap file exists and is non-empty (5 packets * 64 bytes +
	// 24-byte pcap global header > 100 bytes).
	info, err := os.Stat(pcapPath)
	if err != nil {
		t.Fatalf("pcap file not created at %s: %v", pcapPath, err)
	}
	if info.Size() == 0 {
		t.Errorf("pcap file is empty after writer close (output writer may have been skipped)")
	}
	t.Logf("pcap file size: %d bytes (task_id=%s)", info.Size(), out.TaskID)
}

// TestMCP_GenerateTraffic_FlowControl verifies strategy-level and task-level
// flow_control are accepted by the workflow (not rejected by validation).
func TestMCP_GenerateTraffic_FlowControl(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:            "fc-task",
		Protocol:            "tcp",
		Config:              map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
		StrategyFlowControl: &flowControlInput{Type: "flows", Value: 10},
		TaskFlowControl:     &flowControlInput{Type: "flows", Value: 5},
		OutputType:          "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/fc.pcap",
		},
	})
	if err != nil {
		t.Fatalf("generate with flow_control failed: %v", err)
	}

	// Verify the strategy has flow_control stored.
	_, sout, _ := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     out.StrategyID,
	})
	var sd map[string]interface{}
	json.Unmarshal(asRaw(sout.Data), &sd)
	fc, _ := sd["flow_control"].(map[string]interface{})
	if fc == nil {
		t.Fatalf("strategy has no flow_control stored: %s", string(asRaw(sout.Data)))
	}
	if fcType, _ := fc["type"].(string); fcType != "flows" {
		t.Errorf("strategy flow_control.type = %v, want flows", fc["type"])
	}

	// Drain completion.
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
	}
}

// TestMCP_ManageTasks_StopRunning verifies that stop on a running task
// succeeds and transitions the task to "stopped". This complements
// StopFailsNonRunning by verifying the positive path.
func TestMCP_ManageTasks_StopRunning(t *testing.T) {
	env := setupMCPTestWithPlanner(t, &slowMCPPlanner{name: "tcp", delay: 50 * time.Millisecond})
	defer env.cleanup()

	_, sout, _ := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "stoprun-s1",
		Protocol: "tcp",
		Config:   map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	var sd map[string]string
	json.Unmarshal(asRaw(sout.Data), &sd)

	_, tout, _ := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action:      "create",
		Name:        "stoprun-task",
		StrategyIDs: []string{sd["id"]},
		OutputType:  "pcap",
		OutputConfig: &outputConfigInput{PcapPath: env.tmp + "/stoprun.pcap"},
	})
	var td map[string]string
	json.Unmarshal(asRaw(tout.Data), &td)

	env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "start",
		ID:     td["id"],
	})

	// Poll for "running" (deterministic, same pattern as DeleteFailsRunning).
	deadline := time.Now().Add(3 * time.Second)
	running := false
	for time.Now().Before(deadline) {
		_, gout, _ := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
			Action: "get",
			ID:     td["id"],
		})
		var gt map[string]interface{}
		json.Unmarshal(asRaw(gout.Data), &gt)
		if status, _ := gt["status"].(string); status == "running" {
			running = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !running {
		t.Fatal("task never reached running state")
	}

	// Stop should succeed on a running task.
	_, _, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "stop",
		ID:     td["id"],
	})
	if err != nil {
		t.Fatalf("stop running task failed: %v", err)
	}

	// Verify status transitioned to "stopped" (or "stopping").
	_, gout, _ := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "get",
		ID:     td["id"],
	})
	var gt map[string]interface{}
	json.Unmarshal(asRaw(gout.Data), &gt)
	status, _ := gt["status"].(string)
	if status != "stopped" && status != "stopping" {
		t.Errorf("expected stopped/stopping, got %q", status)
	}

	// Drain any completion signal (task may have completed before stop took effect).
	select {
	case <-env.done:
	case <-time.After(2 * time.Second):
	}
}

// ---------------------------------------------------------------------------
// §4.x pad_min_frame E2E — ARP + real Builder.Build + pcap roundtrip
// ---------------------------------------------------------------------------
//
// These tests exercise the pad_min_frame (Ethernet padding to 60-byte minimum)
// feature end-to-end through the MCP generate_traffic tool surface. They use
// the real ARP planner (arp.NewPlanner) and the production BuildFunc wrapper
// (replay.NewBuildFunc(builder.Build)), so Builder.Build is actually invoked
// and its padding logic is exercised. Frame lengths are verified by reading
// the pcap output back with pcapgo (pure Go, no tcpdump or root required).
//
// ARP is the natural choice for padding E2E: each ARP frame is 14 (Eth) + 0
// (no L3) + 0 (no L4) + 28 (ARP payload) = 42 bytes natural, clearly below
// the 60-byte IEEE 802.3 minimum, so padding behavior is obvious. The ARP
// planner emits a request (up) + reply (down) by default, so each task
// produces 2 frames.
//
// Three states to verify (matching mapToFlowSpec + Builder.shouldPad):
//   - absent (default): PadMinFrame=nil -> shouldPad=true -> padded to 60
//   - explicit false:   PadMinFrame=*false -> shouldPad=false -> 42 (natural)
//   - explicit true:    PadMinFrame=*true  -> shouldPad=true  -> 60 (matches default)

// TestMCP_GenerateTraffic_PadMinFrame_DefaultON verifies that an ARP task
// with NO pad_min_frame field produces 60-byte frames in the pcap (default
// padding ON, per IEEE 802.3). This is the most common user path — they
// don't set the field, they get spec-compliant frames.
func TestMCP_GenerateTraffic_PadMinFrame_DefaultON(t *testing.T) {
	env := setupMCPTestWithRealBuilder(t)
	defer env.cleanup()

	pcapPath := env.tmp + "/arp-default.pcap"
	_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName: "arp-default",
		Protocol: "arp",
		Config: map[string]interface{}{
			// D-ARP-1 扁平判死后层链形状。
			"layers": []map[string]interface{}{
				{"eth": map[string]interface{}{"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02"}},
				{"arp": map[string]interface{}{"operation": 1}},
			},
		},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: pcapPath,
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete")
	}

	engineTaskID := out.TaskID + "-" + out.StrategyID
	env.eng.UnregisterOutputWriter(engineTaskID)

	lengths := readPcapFrameLengths(t, pcapPath)
	if len(lengths) != 2 {
		t.Fatalf("frame count = %d, want 2 (ARP request + reply)", len(lengths))
	}
	for i, l := range lengths {
		if l != 60 {
			t.Errorf("frame[%d] length = %d, want 60 (default padded)", i, l)
		}
	}
}

// TestMCP_GenerateTraffic_PadMinFrame_False_NoPadding verifies that explicit
// pad_min_frame=false disables padding. Frames are emitted at their natural
// size (42 bytes for ARP). This proves the presence-check in mapToFlowSpec
// (absent vs. explicit false) and the worker propagation (spec.PadMinFrame
// -> config.L2.Pad) both work through the MCP tool surface.
func TestMCP_GenerateTraffic_PadMinFrame_False_NoPadding(t *testing.T) {
	env := setupMCPTestWithRealBuilder(t)
	defer env.cleanup()

	pcapPath := env.tmp + "/arp-nopad.pcap"
	_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName: "arp-nopad",
		Protocol: "arp",
		Config: map[string]interface{}{
			"layers": []map[string]interface{}{
				{"eth": map[string]interface{}{"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02"}},
				{"arp": map[string]interface{}{"operation": 1}},
			}, // D-ARP-1 扁平判死后层链形状
			"pad_min_frame": false,
		},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: pcapPath,
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete")
	}

	engineTaskID := out.TaskID + "-" + out.StrategyID
	env.eng.UnregisterOutputWriter(engineTaskID)

	lengths := readPcapFrameLengths(t, pcapPath)
	if len(lengths) != 2 {
		t.Fatalf("frame count = %d, want 2", len(lengths))
	}
	for i, l := range lengths {
		if l != 42 {
			t.Errorf("frame[%d] length = %d, want 42 (padding disabled, natural size)", i, l)
		}
	}
}

// TestMCP_GenerateTraffic_PadMinFrame_True_ExplicitON verifies that explicit
// pad_min_frame=true matches the default-ON behavior (60-byte frames). This
// guards against a regression where the presence-check treats true the same
// as absent (and a future default-OFF change silently breaks explicit true).
func TestMCP_GenerateTraffic_PadMinFrame_True_ExplicitON(t *testing.T) {
	env := setupMCPTestWithRealBuilder(t)
	defer env.cleanup()

	pcapPath := env.tmp + "/arp-pad.pcap"
	_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName: "arp-pad",
		Protocol: "arp",
		Config: map[string]interface{}{
			"layers": []map[string]interface{}{
				{"eth": map[string]interface{}{"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02"}},
				{"arp": map[string]interface{}{"operation": 1}},
			}, // D-ARP-1 扁平判死后层链形状
			"pad_min_frame": true,
		},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: pcapPath,
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete")
	}

	engineTaskID := out.TaskID + "-" + out.StrategyID
	env.eng.UnregisterOutputWriter(engineTaskID)

	lengths := readPcapFrameLengths(t, pcapPath)
	if len(lengths) != 2 {
		t.Fatalf("frame count = %d, want 2", len(lengths))
	}
	for i, l := range lengths {
		if l != 60 {
			t.Errorf("frame[%d] length = %d, want 60 (explicit pad=true)", i, l)
		}
	}
}

// ---------------------------------------------------------------------------
// §4.x flowb_query_layers — layer registry query (P6)
// ---------------------------------------------------------------------------

// TestMCP_QueryLayers_ListAll asserts the full registry: every registered
// layer name appears in the list view. The tool's list is the only surface
// through which an LLM discovers layer names, so the registry must be
// complete or layer-chain configs cannot be written.
func TestMCP_QueryLayers_ListAll(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleQueryLayers(context.Background(), nil, queryLayersInput{})
	if err != nil {
		t.Fatalf("query_layers (list): %v", err)
	}
	if out.Action != "query_layers" {
		t.Errorf("action = %q, want query_layers", out.Action)
	}
	var views []map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &views); err != nil {
		t.Fatalf("list data not a JSON array: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	if len(views) == 0 {
		t.Fatal("list view is empty")
	}
	got := map[string]bool{}
	for _, v := range views {
		name, _ := v["name"].(string)
		got[name] = true
	}
	want := layers.DefaultRegistry().List()
	if len(want) == 0 {
		t.Fatal("registry is empty")
	}
	if len(views) != len(want) {
		t.Errorf("list view has %d entries, registry has %d (duplicates or extras)", len(views), len(want))
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("list view missing registered layer %q", name)
		}
	}
}

// TestMCP_QueryLayers_LookupTCP asserts the single-layer view exposes the
// tcp schema fields, and that defaults/range bounds appear as JSON numbers
// (the exact form an LLM must send back as config values).
func TestMCP_QueryLayers_LookupTCP(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleQueryLayers(context.Background(), nil, queryLayersInput{Layer: "tcp"})
	if err != nil {
		t.Fatalf("query_layers (tcp): %v", err)
	}
	var view map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &view); err != nil {
		t.Fatalf("tcp data not valid JSON: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	if view["name"] != "tcp" {
		t.Errorf("name = %v, want tcp", view["name"])
	}
	if view["category"] != "transport" {
		t.Errorf("category = %v, want transport", view["category"])
	}
	fields, _ := view["fields"].(map[string]interface{})
	if fields == nil {
		t.Fatalf("fields missing: %s", string(asRaw(out.Data)))
	}
	for _, f := range []string{"src_port", "dst_port", "mss", "window_size", "handshake", "termination", "rst", "initial_seq"} {
		if _, ok := fields[f]; !ok {
			t.Errorf("tcp schema missing field %q", f)
		}
	}
	mss, _ := fields["mss"].(map[string]interface{})
	if mss["default"] != float64(1460) {
		t.Errorf("mss.default = %v, want 1460 (JSON number)", mss["default"])
	}
	if mss["min"] != float64(536) || mss["max"] != float64(65535) {
		t.Errorf("mss min/max = %v/%v, want 536/65535", mss["min"], mss["max"])
	}
}

// TestMCP_QueryLayers_UnknownLayer asserts the negative path: an unknown
// layer name returns CodeInvalidParams with a helpful message, not a panic
// or empty data.
func TestMCP_QueryLayers_UnknownLayer(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleQueryLayers(context.Background(), nil, queryLayersInput{Layer: "no-such-layer"})
	if err == nil {
		t.Fatal("unknown layer returned no error")
	}
	var rpcErr *jsonrpc.Error
	if !errors.As(err, &rpcErr) {
		t.Fatalf("error type = %T, want *jsonrpc.Error", err)
	}
	if rpcErr.Code != jsonrpc.CodeInvalidParams {
		t.Errorf("code = %v, want CodeInvalidParams", rpcErr.Code)
	}
	if !strings.Contains(rpcErr.Message, "no-such-layer") {
		t.Errorf("message = %q, must name the unknown layer", rpcErr.Message)
	}
}

// TestMCP_QueryLayers_ViewMatchesRegistry asserts the emitted view is
// content-consistent with the registry: every field of the layer appears in
// the view with the same default/type, and enum-default layers (http, tls)
// keep their string enum defaults. Byte equality is impossible here — the
// view is decoded into maps whose key order is random — so this asserts the
// semantic contract instead.
func TestMCP_QueryLayers_ViewMatchesRegistry(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	for _, layer := range []string{"ip", "tcp", "http", "tls", "smb", "tftp"} {
		_, out, err := env.srv.handleQueryLayers(context.Background(), nil, queryLayersInput{Layer: layer})
		if err != nil {
			t.Fatalf("query_layers (%s): %v", layer, err)
		}
		var view map[string]interface{}
		if err := json.Unmarshal(asRaw(out.Data), &view); err != nil {
			t.Fatalf("%s view not valid JSON: %v", layer, err)
		}
		fields, _ := view["fields"].(map[string]interface{})
		if fields == nil {
			t.Fatalf("%s view missing fields: %s", layer, string(asRaw(out.Data)))
		}

		schema, ok := layers.DefaultRegistry().Get(layer)
		if !ok {
			t.Fatalf("registry has no layer %s", layer)
		}
		// The view must not drop or invent fields: both directions of the
		// field map are compared for equality.
		if len(fields) != len(schema.Fields) {
			t.Errorf("%s view exposes %d fields, registry has %d (dropped or invented)", layer, len(fields), len(schema.Fields))
		}
		// Dependency fields are the tool's core purpose: an LLM must learn
		// what a layer sits on. Assert each dependency list survives into the
		// view (deleting the copy in buildLayerSchemaView must fail here).
		depOn, _ := view["depends_on"].([]interface{})
		if !stringSetEqual(depOn, schema.DependsOn) {
			t.Errorf("%s depends_on = %v, want %v", layer, depOn, schema.DependsOn)
		}
		transOn, _ := view["transport_on"].([]interface{})
		if !stringSetEqual(transOn, schema.TransportOn) {
			t.Errorf("%s transport_on = %v, want %v", layer, transOn, schema.TransportOn)
		}
		optOn, _ := view["optional_on"].([]interface{})
		if !stringSetEqual(optOn, schema.OptionalOn) {
			t.Errorf("%s optional_on = %v, want %v", layer, optOn, schema.OptionalOn)
		}
		for name, fs := range schema.Fields {
			v, ok := fields[name]
			if !ok {
				t.Errorf("%s view missing field %q", layer, name)
				continue
			}
			fm, _ := v.(map[string]interface{})
			if fm == nil {
				t.Errorf("%s field %q not an object: %v", layer, name, v)
				continue
			}
			if fm["type"] != fs.Type {
				t.Errorf("%s.%s type = %v, want %q", layer, name, fm["type"], fs.Type)
			}
			// Defaults re-marshal through interface{}: strings stay strings,
			// bools stay bools, uint8/16/32 become float64, maps/lists keep
			// shape. Compare via a JSON round-trip of the Go default.
			rawDefault, err := json.Marshal(fs.Default)
			if err != nil {
				t.Fatalf("%s.%s default marshal: %v", layer, name, err)
			}
			gotDefault, err := json.Marshal(fm["default"])
			if err != nil {
				t.Fatalf("%s.%s view default marshal: %v", layer, name, err)
			}
			// 0 defaults are emitted with omitempty and absent from the view.
			if string(rawDefault) != "0" && string(rawDefault) != `""` && string(rawDefault) != "false" {
				if string(gotDefault) != string(rawDefault) {
					t.Errorf("%s.%s default = %s, want %s", layer, name, string(gotDefault), string(rawDefault))
				}
			}
		}
	}
}

// TestMCP_QueryLayers_CreateStrategyWithLayers drives the full path:
// flowb_query_layers output -> manage_strategies create with a layer-chain
// config -> strategy persisted with a top-level layers key. Guards against
// the tool description and the backend validation diverging.
func TestMCP_QueryLayers_CreateStrategyWithLayers(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, lout, err := env.srv.handleQueryLayers(context.Background(), nil, queryLayersInput{})
	if err != nil {
		t.Fatalf("query_layers (list): %v", err)
	}
	if !strings.Contains(string(asRaw(lout.Data)), `"name":"tcp"`) {
		t.Fatalf("registry list does not teach the tcp layer: %s", string(asRaw(lout.Data)))
	}

	_, out, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "layered-s1",
		Mode:     "synth",
		Protocol: "http",
		Config: map[string]interface{}{
			"layers": []interface{}{
				map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.9"}},
				map[string]interface{}{"tcp": map[string]interface{}{"dst_port": 8080}},
				map[string]interface{}{"http": map[string]interface{}{"method": "GET", "uri": "/x"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("create with layers: %v", err)
	}
	var created map[string]string
	json.Unmarshal(asRaw(out.Data), &created)
	sid := created["id"]
	if sid == "" {
		t.Fatal("create with layers did not return id")
	}

	_, gout, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     sid,
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var stored map[string]interface{}
	json.Unmarshal(asRaw(gout.Data), &stored)
	cfg, _ := stored["config"].(map[string]interface{})
	if _, ok := cfg["layers"]; !ok {
		t.Fatalf("stored config has no layers key: %s", string(asRaw(gout.Data)))
	}
}

// stringSetEqual compares a decoded JSON array ([]interface{} of strings)
// with a []string, treating them as sets.
func stringSetEqual(got []interface{}, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	m := map[string]bool{}
	for _, s := range want {
		m[s] = true
	}
	for _, g := range got {
		gs, ok := g.(string)
		if !ok || !m[gs] {
			return false
		}
	}
	return true
}

// TestMCP_QueryLayers_TunnelInnerAttached asserts the tunnel nesting view:
// a tunnel layer (gre) exposes its InnerRequired layer as a nested "inner"
// entry, and a tunnel with no InnerRequired (tls) has no inner entries.
// This exercises withTunnelInner, the only untested branch of the tool.
func TestMCP_QueryLayers_TunnelInnerAttached(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, gout, err := env.srv.handleQueryLayers(context.Background(), nil, queryLayersInput{Layer: "gre"})
	if err != nil {
		t.Fatalf("query_layers (gre): %v", err)
	}
	var greView map[string]interface{}
	if err := json.Unmarshal(asRaw(gout.Data), &greView); err != nil {
		t.Fatalf("gre data not valid JSON: %v", err)
	}
	inner, _ := greView["inner"].([]interface{})
	foundIP := false
	for _, iv := range inner {
		m, _ := iv.(map[string]interface{})
		if m["name"] == "ip" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("gre view inner = %v, must nest the InnerRequired ip layer", inner)
	}

	_, tout, err := env.srv.handleQueryLayers(context.Background(), nil, queryLayersInput{Layer: "tls"})
	if err != nil {
		t.Fatalf("query_layers (tls): %v", err)
	}
	var tlsView map[string]interface{}
	if err := json.Unmarshal(asRaw(tout.Data), &tlsView); err != nil {
		t.Fatalf("tls data not valid JSON: %v", err)
	}
	if _, ok := tlsView["inner"]; ok {
		t.Errorf("tls view inner = %v, want absent (no InnerRequired)", tlsView["inner"])
	}
}

// TestMCP_QueryLayers_SDKCallToolNotBase64 is a regression test for a real
// bug found in review: the handler returned json.RawMessage in the output
// struct, and the SDK's CallTool path re-marshals the struct, base64-encoding
// the RawMessage. The LLM would have received a base64 blob instead of the
// layer list. This drives the full SDK path (CallTool) and asserts the
// returned content contains real layer JSON, not base64.
func TestMCP_QueryLayers_SDKCallToolNotBase64(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	ts, session := newHTTPTestServer(t, env, "test-secret", []string{"*"})
	defer ts.Close()
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "flowb_query_layers",
		Arguments: map[string]interface{}{"layer": "tcp"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if out.IsError {
		t.Fatalf("tool error: %s", out.Content)
	}
	// The structured content must embed the actual layer JSON, not a
	// base64-encoded RawMessage (which would not contain the substring
	// `"name":"tcp"`). Also must not be "{}" (dataOnly/manage schema quirks).
	text := ""
	for _, c := range out.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text = tc.Text
			break
		}
	}
	if !strings.Contains(text, `"name":"tcp"`) {
		t.Errorf("CallTool content missing layer JSON: %q", text)
	}
}

// TestMCP_QueryLayers_InvalidChainCreateRejected is a negative-path test:
// a layer chain that fails validation (two terminal layers) must make
// manage_strategies create fail. Per CLAUDE.md §2, a happy-path-only create
// test would pass even if layer-chain validation were gutted.
func TestMCP_QueryLayers_InvalidChainCreateRejected(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "bad-chain",
		Mode:     "synth",
		Protocol: "http",
		Config: map[string]interface{}{
			"layers": []interface{}{
				map[string]interface{}{"ip": map[string]interface{}{}},
				map[string]interface{}{"tcp": map[string]interface{}{}},
				map[string]interface{}{"http": map[string]interface{}{}},
				map[string]interface{}{"dns": map[string]interface{}{}},
			},
		},
	})
	if err == nil {
		t.Fatal("create with two terminal layers (http+dns) succeeded; layer-chain validation must reject it")
	}
}
