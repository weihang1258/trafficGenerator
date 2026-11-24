package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// flowb_manage_settings - get / update
// ---------------------------------------------------------------------------

func TestMCP_ManageSettings_GetAndUpdate(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Get initial settings (should be defaults from DB seed)
	_, out, err := env.srv.handleManageSettings(context.Background(), nil, manageSettingsInput{
		Action: "get",
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var initial map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &initial); err != nil {
		t.Fatalf("get returned non-object: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	if _, ok := initial["max_tasks"]; !ok {
		t.Errorf("get missing max_tasks: %s", string(asRaw(out.Data)))
	}
	if _, ok := initial["log_level"]; !ok {
		t.Errorf("get missing log_level: %s", string(asRaw(out.Data)))
	}

	// Update max_tasks
	_, out2, err := env.srv.handleManageSettings(context.Background(), nil, manageSettingsInput{
		Action:   "update",
		MaxTasks: 50,
		LogLevel: "warn",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	var updated map[string]interface{}
	if err := json.Unmarshal(asRaw(out2.Data), &updated); err != nil {
		t.Fatalf("update returned non-object: %s", string(asRaw(out2.Data)))
	}
	if updated["max_tasks"] != float64(50) {
		t.Errorf("max_tasks after update: got %v, want 50", updated["max_tasks"])
	}
	if updated["log_level"] != "warn" {
		t.Errorf("log_level after update: got %v, want warn", updated["log_level"])
	}

	// Verify the update persisted via a fresh Get
	_, out3, err := env.srv.handleManageSettings(context.Background(), nil, manageSettingsInput{
		Action: "get",
	})
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	var after map[string]interface{}
	json.Unmarshal(asRaw(out3.Data), &after)
	if after["max_tasks"] != float64(50) {
		t.Errorf("max_tasks persisted: got %v, want 50", after["max_tasks"])
	}
}

func TestMCP_ManageSettings_InvalidAction(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageSettings(context.Background(), nil, manageSettingsInput{
		Action: "bogus",
	})
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}

func TestMCP_ManageSettings_InvalidLogLevel(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// log_level validation happens in the backend (logger.SetLevel).
	// An invalid level should produce a backend 400 -> MCP error.
	_, _, err := env.srv.handleManageSettings(context.Background(), nil, manageSettingsInput{
		Action:   "update",
		LogLevel: "invalid-level",
	})
	if err == nil {
		t.Fatal("expected error for invalid log_level, got nil")
	}
}

// ---------------------------------------------------------------------------
// flowb_manage_profile - get / update / delete
// ---------------------------------------------------------------------------

func TestMCP_ManageProfile_Get(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleManageProfile(context.Background(), nil, manageProfileInput{
		Action: "get",
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var profile map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &profile); err != nil {
		t.Fatalf("get returned non-object: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	if profile["username"] != "mcp-test-svc" {
		t.Errorf("username: got %v, want mcp-test-svc", profile["username"])
	}
	if profile["role"] != "user" {
		t.Errorf("role: got %v, want user", profile["role"])
	}
	if profile["user_id"] != "svc-user-1" {
		t.Errorf("user_id: got %v, want svc-user-1", profile["user_id"])
	}
}

func TestMCP_ManageProfile_UpdateEmail(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageProfile(context.Background(), nil, manageProfileInput{
		Action: "update",
		Email:  "new-email@test.local",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	// Verify via get
	_, out, err := env.srv.handleManageProfile(context.Background(), nil, manageProfileInput{
		Action: "get",
	})
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	var profile map[string]interface{}
	json.Unmarshal(asRaw(out.Data), &profile)
	if profile["email"] != "new-email@test.local" {
		t.Errorf("email after update: got %v, want new-email@test.local", profile["email"])
	}
}

func TestMCP_ManageProfile_InvalidAction(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageProfile(context.Background(), nil, manageProfileInput{
		Action: "bogus",
	})
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}

// ---------------------------------------------------------------------------
// flowb_manage_port_groups - create / list / get / delete
// ---------------------------------------------------------------------------

func TestMCP_ManagePortGroups_CRUD(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Create
	_, out, err := env.srv.handleManagePortGroups(context.Background(), nil, managePortGroupsInput{
		Action: "create",
		Ports: []portGroupPort{
			{Interface: "eth0", Weight: 1},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var createData map[string]interface{}
	json.Unmarshal(asRaw(out.Data), &createData)
	id, ok := createData["id"].(string)
	if !ok || id == "" {
		t.Fatalf("create did not return id: %s", string(asRaw(out.Data)))
	}

	// List
	_, out2, err := env.srv.handleManagePortGroups(context.Background(), nil, managePortGroupsInput{
		Action: "list",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listData []map[string]interface{}
	if err := json.Unmarshal(asRaw(out2.Data), &listData); err != nil {
		t.Fatalf("list returned non-array: %s (err: %v)", string(asRaw(out2.Data)), err)
	}
	found := false
	for _, pg := range listData {
		if pg["id"] == id {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created port group %s not in list: %s", id, string(asRaw(out2.Data)))
	}

	// Get
	_, out3, err := env.srv.handleManagePortGroups(context.Background(), nil, managePortGroupsInput{
		Action: "get",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var getData map[string]interface{}
	json.Unmarshal(asRaw(out3.Data), &getData)
	if getData["id"] != id {
		t.Errorf("get returned wrong id: %v", getData["id"])
	}

	// Delete
	_, _, err = env.srv.handleManagePortGroups(context.Background(), nil, managePortGroupsInput{
		Action: "delete",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Verify deletion via get (should fail)
	_, _, err = env.srv.handleManagePortGroups(context.Background(), nil, managePortGroupsInput{
		Action: "get",
		ID:     id,
	})
	if err == nil {
		t.Error("get after delete should fail, got nil error")
	}
}

func TestMCP_ManagePortGroups_InvalidAction(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManagePortGroups(context.Background(), nil, managePortGroupsInput{
		Action: "bogus",
	})
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tool registration smoke test - verifies all registered tools appear in the
// MCP server's tool list. Catches registration wiring bugs.
// ---------------------------------------------------------------------------

func TestMCP_AllRegisteredToolsAppear(t *testing.T) {
	srv := newTransportTestServer(t)

	// 走真实 ListTools（内存传输），断言全部工具都对外可见。此前这个测试
	// 只把工具名存进一个变量再 _ = 掉——断言数为零，注册漏了也全绿。
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	go func() { _ = srv.mcpServer.Run(ctx, st) }()
	sc, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sc.Close()
	resp, err := sc.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	advertised := make(map[string]bool, len(resp.Tools))
	for _, tl := range resp.Tools {
		advertised[tl.Name] = true
	}

	expectedTools := []string{
		"flowb_manage_strategies",
		"flowb_manage_tasks",
		"flowb_generate_traffic",
		"flowb_manage_settings",
		"flowb_manage_profile",
		"flowb_manage_port_groups",
		"flowb_manage_pcaps",
		"flowb_query_layers",
		"flowb_manage_users",
		"flowb_manage_auth",
	}
	for _, name := range expectedTools {
		if !advertised[name] {
			t.Errorf("tool %q is not advertised by the server (got %d tools)", name, len(resp.Tools))
		}
	}
	// 反向断言：每个对外工具都必须带输入 schema，否则模型无从填参。
	for _, tl := range resp.Tools {
		if tl.InputSchema == nil {
			t.Errorf("tool %q has no input schema", tl.Name)
		}
	}
}
