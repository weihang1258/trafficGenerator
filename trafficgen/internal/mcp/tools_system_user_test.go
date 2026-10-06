package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// flowb_query_system - 8 actions
// ---------------------------------------------------------------------------

func TestMCP_QuerySystem_Status(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleQuerySystem(context.Background(), nil, querySystemInput{
		Action: "status",
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var status map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &status); err != nil {
		t.Fatalf("status returned non-object: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	// Engine is started in setupMCPTest, so running should be true.
	if status["running"] != true {
		t.Errorf("running: got %v, want true", status["running"])
	}
	if _, ok := status["active_tasks"]; !ok {
		t.Errorf("status missing active_tasks: %s", string(asRaw(out.Data)))
	}
	if _, ok := status["uptime"]; !ok {
		t.Errorf("status missing uptime: %s", string(asRaw(out.Data)))
	}
}

func TestMCP_QuerySystem_Protocols(t *testing.T) {
	env := setupMCPTestWithPlanner(t, &mockMCPPlanner{name: "udp"})
	// 包级跑时其他测试会注册额外 planner；本测试自己注册 udp 保证独立
	// 可跑（原先依赖包内其他测试注册的 "udp"，单跑时报 missing "udp"）。
	env.eng.RegisterPlanner(&mockMCPPlanner{name: "tcp"})
	defer env.cleanup()

	_, out, err := env.srv.handleQuerySystem(context.Background(), nil, querySystemInput{
		Action: "protocols",
	})
	if err != nil {
		t.Fatalf("protocols: %v", err)
	}
	var protocols []string
	if err := json.Unmarshal(asRaw(out.Data), &protocols); err != nil {
		t.Fatalf("protocols returned non-array: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	// OBS-1（2026-10-06）：清单对齐 query_layers examples 的应用协议面——
	// 纯传输层 udp 剔除（仍是合法层，只是不作为独立协议列出），tcp 保留。
	seen := map[string]bool{}
	for _, p := range protocols {
		seen[p] = true
	}
	if !seen["tcp"] {
		t.Errorf("protocols missing %q: %v", "tcp", protocols)
	}
	if seen["udp"] {
		t.Errorf("udp must not be listed (transport-only layer, OBS-1): %v", protocols)
	}
}

func TestMCP_QuerySystem_Stats(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleQuerySystem(context.Background(), nil, querySystemInput{
		Action: "stats",
	})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	var stats map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &stats); err != nil {
		t.Fatalf("stats returned non-object: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	for _, key := range []string{"packets_sent", "bytes_sent", "current_pps", "current_bps", "protocols", "buffer"} {
		if _, ok := stats[key]; !ok {
			t.Errorf("stats missing %q: %s", key, string(asRaw(out.Data)))
		}
	}
}

func TestMCP_QuerySystem_Health(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleQuerySystem(context.Background(), nil, querySystemInput{
		Action: "health",
	})
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	var health map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &health); err != nil {
		t.Fatalf("health returned non-object: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	if health["status"] != "healthy" {
		t.Errorf("health.status: got %v, want healthy", health["status"])
	}
}

func TestMCP_QuerySystem_Ready(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleQuerySystem(context.Background(), nil, querySystemInput{
		Action: "ready",
	})
	if err != nil {
		t.Fatalf("ready: %v", err)
	}
	var ready map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &ready); err != nil {
		t.Fatalf("ready returned non-object: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	// Engine is started in setupMCPTest, so ready check should pass.
	if ready["status"] != "ready" {
		t.Errorf("ready.status: got %v, want ready", ready["status"])
	}
}

func TestMCP_QuerySystem_Interfaces(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleQuerySystem(context.Background(), nil, querySystemInput{
		Action: "interfaces",
	})
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	// Test env's ifaceMgr is empty (NewManager doesn't scan), so we expect
	// an empty array -- but it must be a valid array, not null or an error.
	var interfaces []map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &interfaces); err != nil {
		t.Fatalf("interfaces returned non-array: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	// portSched is nil in test env, so the InUse/Allocations path is skipped.
	// We just verify the call succeeds and returns valid JSON.
}

func TestMCP_QuerySystem_Ports(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleQuerySystem(context.Background(), nil, querySystemInput{
		Action: "ports",
	})
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	var ports []map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &ports); err != nil {
		t.Fatalf("ports returned non-array: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	// Test env has no ports seeded; empty array is expected.
}

func TestMCP_QuerySystem_InvalidAction(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleQuerySystem(context.Background(), nil, querySystemInput{
		Action: "bogus",
	})
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}

// ---------------------------------------------------------------------------
// flowb_manage_users - 5 actions, all admin-only (403 in service account mode)
// ---------------------------------------------------------------------------

func TestMCP_ManageUsers_List_ForbiddenInServiceMode(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Service account role=user; backend UserHandler.List requires admin.
	// Expected: error with "admin access required" message.
	_, _, err := env.srv.handleManageUsers(context.Background(), nil, manageUsersInput{
		Action: "list",
	})
	if err == nil {
		t.Fatal("expected error for list in service account mode, got nil")
	}
}

func TestMCP_ManageUsers_Get_ForbiddenInServiceMode(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageUsers(context.Background(), nil, manageUsersInput{
		Action: "get",
		ID:     "any-id",
	})
	if err == nil {
		t.Fatal("expected error for get in service account mode, got nil")
	}
}

func TestMCP_ManageUsers_InvalidAction(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageUsers(context.Background(), nil, manageUsersInput{
		Action: "bogus",
	})
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}
