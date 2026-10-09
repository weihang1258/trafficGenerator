package mcp

// output_config.ports 自动建端口组测试（spec = 会话确认的方案口径）。
//
// § spec 行转用例：
//  1. 单网卡 ports → 组建成 + 任务建成 + 响应回填 id/reused=false，任务落库
//     output_config 为消化后形状（含 port_group_id、无 ports 键）。
//  2. 多网卡 + 权重 → 建组参数原样落库（权重保留）；乱序重提交命中同一组
//     （服务端按 interface 名排序哈希），reused=true，不增新行。
//  3. 手动建的同配置组同样被复用（不存在"自动/手动"两套组）。
//  4. ports 与 port_group_id 同给 → InvalidParams，且建组无副作用。
//  5. output_type=pcap 配 ports → InvalidParams。
//  6. ports:[] 空数组 → InvalidParams。
//  7. ports[i].interface 空 → InvalidParams。
//  8. manage_tasks create / create_batch 带 ports 同样生效。
//  9. replay_pcap 带 ports 同样生效（独立接线点，必须单测）。
//
// 运行：go test ./internal/mcp/ -run 'TestMCP_Ports' -v

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/replay"
	"github.com/trafficgen/trafficgen/internal/storage"
)

func portsTestConfig() map[string]interface{} {
	return map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}}
}

func countPortGroups(t *testing.T, env *testMCPEnv) int64 {
	t.Helper()
	var n int64
	if err := env.db.Model(&storage.PortGroupModel{}).Count(&n).Error; err != nil {
		t.Fatalf("count port groups: %v", err)
	}
	return n
}

func loadPortGroup(t *testing.T, env *testMCPEnv, id string) storage.PortGroupModel {
	t.Helper()
	var pg storage.PortGroupModel
	if err := env.db.First(&pg, "id = ?", id).Error; err != nil {
		t.Fatalf("load port group %s: %v", id, err)
	}
	return pg
}

func loadTaskOutputConfig(t *testing.T, env *testMCPEnv, taskID string) map[string]interface{} {
	t.Helper()
	var tm storage.TaskModel
	if err := env.db.First(&tm, "id = ?", taskID).Error; err != nil {
		t.Fatalf("load task %s: %v", taskID, err)
	}
	var oc map[string]interface{}
	if err := json.Unmarshal([]byte(tm.OutputConfig), &oc); err != nil {
		t.Fatalf("decode task output_config: %v", err)
	}
	return oc
}

func TestMCP_PortsAutoCreate_HappyPath(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	oc := &outputConfigInput{Ports: []portGroupPort{{Interface: "stubif0", Weight: 1}}}
	run, _ := env.srv.createStrategyAndTask(context.Background(), nil, "test",
		"ports-happy", "tcp", portsTestConfig(),
		&flowControlInput{Type: "flows", Value: 1}, nil, "port_group", oc)
	if run.Err != nil {
		t.Fatalf("createStrategyAndTask: %v", run.Err)
	}
	if run.TaskID == "" {
		t.Fatal("missing task id")
	}
	if run.PortGroupID == "" {
		t.Fatal("missing port_group_id echo")
	}
	if run.PortGroupReused {
		t.Error("fresh group reported reused=true")
	}

	pg := loadPortGroup(t, env, run.PortGroupID)
	if !strings.Contains(pg.PortsConfig, "stubif0") {
		t.Errorf("group ports_config = %s, want stubif0", pg.PortsConfig)
	}

	stored := loadTaskOutputConfig(t, env, run.TaskID)
	if stored["port_group_id"] != run.PortGroupID {
		t.Errorf("stored port_group_id = %v, want %s", stored["port_group_id"], run.PortGroupID)
	}
	if _, ok := stored["ports"]; ok {
		t.Errorf("stored output_config still has ports key: %v", stored)
	}
}

func TestMCP_PortsAutoCreate_MultiNICWeightsAndReorderReuse(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	mk := func(a string, aw int, b string, bw int) *outputConfigInput {
		return &outputConfigInput{Ports: []portGroupPort{
			{Interface: a, Weight: aw},
			{Interface: b, Weight: bw},
		}}
	}
	run1, _ := env.srv.createStrategyAndTask(context.Background(), nil, "test",
		"ports-multi-1", "tcp", portsTestConfig(),
		&flowControlInput{Type: "flows", Value: 1}, nil, "port_group", mk("ethB", 3, "ethA", 1))
	if run1.Err != nil {
		t.Fatalf("first: %v", run1.Err)
	}
	pg := loadPortGroup(t, env, run1.PortGroupID)
	// 权重必须原样落库（不是全 1 拍平）。
	var cfgs []map[string]interface{}
	if err := json.Unmarshal([]byte(pg.PortsConfig), &cfgs); err != nil {
		t.Fatalf("decode ports_config: %v", err)
	}
	got := map[string]float64{}
	for _, c := range cfgs {
		got[c["interface"].(string)] = c["weight"].(float64)
	}
	if got["ethB"] != 3 || got["ethA"] != 1 {
		t.Errorf("weights = %v, want ethB=3 ethA=1", got)
	}

	// 乱序重提交 → 同一组，reused=true，不增行。
	run2, _ := env.srv.createStrategyAndTask(context.Background(), nil, "test",
		"ports-multi-2", "tcp", portsTestConfig(),
		&flowControlInput{Type: "flows", Value: 1}, nil, "port_group", mk("ethA", 1, "ethB", 3))
	if run2.Err != nil {
		t.Fatalf("second: %v", run2.Err)
	}
	if run2.PortGroupID != run1.PortGroupID {
		t.Errorf("reorder reuse: got %s, want %s", run2.PortGroupID, run1.PortGroupID)
	}
	if !run2.PortGroupReused {
		t.Error("reorder reuse reported reused=false")
	}
	if n := countPortGroups(t, env); n != 1 {
		t.Errorf("group rows = %d, want 1 (reorder must reuse)", n)
	}
	// 不同权重 = 不同组（服务端幂等键含 weight）：权重翻转必须建新组。
	nwBefore := countPortGroups(t, env)
	run3, _ := env.srv.createStrategyAndTask(context.Background(), nil, "test",
		"ports-multi-3", "tcp", portsTestConfig(),
		&flowControlInput{Type: "flows", Value: 1}, nil, "port_group", mk("ethA", 3, "ethB", 1))
	if run3.Err != nil {
		t.Fatalf("third: %v", run3.Err)
	}
	if run3.PortGroupID == run1.PortGroupID {
		t.Errorf("weight-flipped reuse: got same group %s, want a different group", run3.PortGroupID)
	}
	if run3.PortGroupReused {
		t.Error("weight-flipped fresh group reported reused=true")
	}
	if n := countPortGroups(t, env); n != nwBefore+1 {
		t.Errorf("group rows %d -> %d, want +1 for different weights", nwBefore, n)
	}
}

func TestMCP_PortsAutoCreate_ReusesManualGroup(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, mout, err := env.srv.handleManagePortGroups(context.Background(), nil, managePortGroupsInput{
		Action: "create",
		Ports:  []portGroupPort{{Interface: "ethM", Weight: 2}},
	})
	if err != nil {
		t.Fatalf("manual create: %v", err)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(asRaw(mout.Data), &created); err != nil || created.ID == "" {
		t.Fatalf("manual create returned no id: %s (err=%v)", string(asRaw(mout.Data)), err)
	}

	run, _ := env.srv.createStrategyAndTask(context.Background(), nil, "test",
		"ports-manual", "tcp", portsTestConfig(),
		&flowControlInput{Type: "flows", Value: 1}, nil, "port_group",
		&outputConfigInput{Ports: []portGroupPort{{Interface: "ethM", Weight: 2}}})
	if run.Err != nil {
		t.Fatalf("createStrategyAndTask: %v", run.Err)
	}
	if run.PortGroupID != created.ID {
		t.Errorf("manual reuse: got %s, want %s", run.PortGroupID, created.ID)
	}
	if !run.PortGroupReused {
		t.Error("manual reuse reported reused=false")
	}
	if n := countPortGroups(t, env); n != 1 {
		t.Errorf("group rows = %d, want 1", n)
	}
}

func TestMCP_PortsAutoCreate_MutualExclusion(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	nBefore := countPortGroups(t, env)
	run, _ := env.srv.createStrategyAndTask(context.Background(), nil, "test",
		"ports-mutex", "tcp", portsTestConfig(),
		&flowControlInput{Type: "flows", Value: 1}, nil, "port_group",
		&outputConfigInput{
			PortGroupID: "pg-x",
			Ports:       []portGroupPort{{Interface: "ethX", Weight: 1}},
		})
	if run.Err == nil {
		t.Fatal("expected mutual-exclusion error, got nil")
	}
	if !strings.Contains(run.Err.Error(), "mutually exclusive") {
		t.Errorf("error = %q, want mutual-exclusion message", run.Err.Error())
	}
	// 策略已建（调用方负责清理是既有语义），但组必须一个没建。
	if run.StrategyID == "" {
		t.Error("strategy id lost on ports failure (caller needs it for cleanup)")
	}
	if n := countPortGroups(t, env); n != nBefore {
		t.Errorf("group rows %d -> %d on rejected call, want no side effect", nBefore, n)
	}
}

func TestMCP_PortsAutoCreate_WrongOutputType(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	run, _ := env.srv.createStrategyAndTask(context.Background(), nil, "test",
		"ports-pcap", "tcp", portsTestConfig(),
		&flowControlInput{Type: "flows", Value: 1}, nil, "pcap",
		&outputConfigInput{Ports: []portGroupPort{{Interface: "ethX", Weight: 1}}})
	if run.Err == nil {
		t.Fatal("expected output_type error, got nil")
	}
	if !strings.Contains(run.Err.Error(), "requires output_type=port_group or both") {
		t.Errorf("error = %q, want output_type complaint", run.Err.Error())
	}
}

func TestMCP_PortsAutoCreate_EmptyPorts(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	run, _ := env.srv.createStrategyAndTask(context.Background(), nil, "test",
		"ports-empty", "tcp", portsTestConfig(),
		&flowControlInput{Type: "flows", Value: 1}, nil, "port_group",
		&outputConfigInput{Ports: []portGroupPort{}})
	if run.Err == nil {
		t.Fatal("expected empty-ports error, got nil")
	}
	if !strings.Contains(run.Err.Error(), "must not be empty") {
		t.Errorf("error = %q, want empty complaint", run.Err.Error())
	}
}

func TestMCP_PortsAutoCreate_EmptyInterface(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	run, _ := env.srv.createStrategyAndTask(context.Background(), nil, "test",
		"ports-noiface", "tcp", portsTestConfig(),
		&flowControlInput{Type: "flows", Value: 1}, nil, "port_group",
		&outputConfigInput{Ports: []portGroupPort{{Interface: "", Weight: 1}}})
	if run.Err == nil {
		t.Fatal("expected empty-interface error, got nil")
	}
	if !strings.Contains(run.Err.Error(), "ports[0].interface is required") {
		t.Errorf("error = %q, want interface complaint", run.Err.Error())
	}
}

func TestMCP_ManageTasks_Create_WithPorts(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, sout, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "create", Name: "ports-mt", Mode: "synth", Protocol: "tcp",
		Config: map[string]interface{}{"layers": []interface{}{map[string]interface{}{"tcp": map[string]interface{}{}}}},
	})
	if err != nil {
		t.Fatalf("create strategy: %v", err)
	}
	var sd struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(asRaw(sout.Data), &sd); err != nil || sd.ID == "" {
		t.Fatalf("strategy returned no id: %s", string(asRaw(sout.Data)))
	}

	_, tout, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "create", Name: "ports-mt-task", StrategyIDs: []string{sd.ID},
		OutputType:   "port_group",
		OutputConfig: &outputConfigInput{Ports: []portGroupPort{{Interface: "ethT", Weight: 1}}},
	})
	if err != nil {
		t.Fatalf("manage_tasks create: %v", err)
	}
	var td struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(asRaw(tout.Data), &td); err != nil || td.ID == "" {
		t.Fatalf("task returned no id: %s", string(asRaw(tout.Data)))
	}
	stored := loadTaskOutputConfig(t, env, td.ID)
	if stored["port_group_id"] == nil || stored["port_group_id"] == "" {
		t.Errorf("stored output_config missing port_group_id: %v", stored)
	}
	if _, ok := stored["ports"]; ok {
		t.Errorf("stored output_config still has ports key: %v", stored)
	}
	loadPortGroup(t, env, stored["port_group_id"].(string))
}

func TestMCP_ManageTasks_CreateBatch_WithPorts(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// CreateBatch 在 Create 期即建真实 writer（与 Create 的 Start 期两套
	// 时序，均已钉在 rest/task_both_test.go）：单元环境无真实 NIC，直接
	// 带 ports 调 create_batch 必在 writer 创建失败——这正是 CreateBatch 的
	// 既有行为（与 ports 无关，传 port_group_id 同样失败）。本例验证
	// handleManageTasks 接线点已调 resolve：复用上一步 resolve 出的组
	// （幂等命中 reused=true），再以消化后形状调 create_batch，失败必须
	// 是 writer 错误而非 output_config 形状错误，且组行数不再增长。
	oc := &outputConfigInput{Ports: []portGroupPort{{Interface: "ethB", Weight: 1}}}
	pgID, reused, rerr := env.srv.resolveOutputConfigPorts(context.Background(), "port_group", oc)
	if rerr != nil {
		t.Fatalf("resolve: %v", rerr)
	}
	if pgID == "" || reused {
		t.Fatalf("resolve = (%q, reused=%v), want fresh id", pgID, reused)
	}
	if oc.PortGroupID != pgID || oc.Ports != nil {
		t.Fatalf("resolve digest = %+v, want {PortGroupID set, Ports nil}", oc)
	}
	nBefore := countPortGroups(t, env)
	batch := map[string]interface{}{
		"classes": []map[string]interface{}{
			{
				"id": "c1", "type": "tcp", "bps": "1m",
				"flow_count": 2,
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
	_, tout, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "create_batch", Name: "ports-batch", Batch: batch,
		OutputType:   "port_group",
		OutputConfig: &outputConfigInput{Ports: []portGroupPort{{Interface: "ethB", Weight: 1}}},
	})
	// 复用命中：handleManageTasks 内 resolve 必须把 ethB 组消化成既有
	// pgID 再调 CreateBatch——失败只能是 writer 建网卡失败，不能是形状错。
	if err == nil {
		t.Fatalf("expected writer failure (no real NIC), got success: %s", string(asRaw(tout.Data)))
	}
	if !strings.Contains(err.Error(), "failed to open interface ethB") {
		t.Errorf("error = %q, want NIC writer failure (proves resolve digested ports to the existing group)", err.Error())
	}
	if n := countPortGroups(t, env); n != nBefore {
		t.Errorf("group rows %d -> %d, want reuse (no new row)", nBefore, n)
	}
}

func TestMCP_ReplayPcap_WithPorts(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	assetID := importTestPcap(t, env)
	env.eng.SetReplayPlanner(replay.NewReplayPlanner(env.db))

	// 虚构网卡：Start 建 writer 必败 → 状态 created + err；断言建组/建任务
	// 两步已在 Start 之前完成且落库形状被消化。
	_, out, err := env.srv.handleReplayPcap(context.Background(), nil, replayPcapInput{
		TaskName:    "replay-ports",
		PcapAssetID: assetID,
		Loop:        ip(1),
		OutputType:  "port_group",
		OutputConfig: &outputConfigInput{
			Ports: []portGroupPort{{Interface: "definitely-not-an-iface-9", Weight: 1}},
		},
	})
	if err == nil {
		t.Fatal("expected Start writer failure on fake iface, got nil")
	}
	if out.TaskID == "" || out.StrategyID == "" {
		t.Fatalf("replay must return ids on Start failure (got %+v, err=%v)", out, err)
	}
	stored := loadTaskOutputConfig(t, env, out.TaskID)
	if stored["port_group_id"] == nil || stored["port_group_id"] == "" {
		t.Errorf("stored output_config missing port_group_id: %v", stored)
	}
	if _, ok := stored["ports"]; ok {
		t.Errorf("stored output_config still has ports key: %v", stored)
	}
	loadPortGroup(t, env, stored["port_group_id"].(string))
}
