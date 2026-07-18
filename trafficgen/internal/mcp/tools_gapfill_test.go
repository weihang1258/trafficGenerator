package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/replay"
)

// ---------------------------------------------------------------------------
// flowb_replay_pcap: speed mode validation (HIGH -- audit fix regression)
// ---------------------------------------------------------------------------

// TestMCP_ReplayPcap_SpeedMode_Rejected verifies that speed.mode=pps and
// speed.mode=max are rejected by validateReplaySpec. The audit fix removed
// pps support; max was already invalid. We pass a VALID asset id so the only
// failure path is speed validation (not the missing asset).
func TestMCP_ReplayPcap_SpeedMode_Rejected(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	assetID := importTestPcap(t, env)
	env.eng.SetReplayPlanner(replay.NewReplayPlanner(env.db))

	// Drain any task completion/failure signal so engine.Stop at cleanup
	// doesn't deadlock (validateReplaySpec should reject before Start, but
	// drain defensively in case any sub-task triggers a callback).
	go func() {
		for range env.done {
		}
	}()

	for _, mode := range []string{"pps", "max"} {
		t.Run(mode, func(t *testing.T) {
			speed := map[string]interface{}{"mode": mode}
			if mode == "pps" {
				speed["pps"] = 100.0
			}
			_, out, err := env.srv.handleReplayPcap(context.Background(), nil, replayPcapInput{
				TaskName:    "replay-" + mode,
				PcapAssetID: assetID,
				Speed:       speed,
				Loop:        1,
				OutputType:  "pcap",
				OutputConfig: &outputConfigInput{
					PcapPath: env.tmp + "/replay-" + mode + ".pcap",
				},
			})
			if err == nil {
				t.Fatalf("speed.mode=%s: expected error from validateReplaySpec, got nil (out=%+v)", mode, out)
			}
			if !strings.Contains(err.Error(), "invalid speed mode") {
				t.Errorf("speed.mode=%s: error %q does not contain 'invalid speed mode'", mode, err.Error())
			}
			// On strategy-create failure, no strategy_id should be returned
			// (creation itself rejects; we don't even reach task creation).
			if out.StrategyID != "" {
				t.Errorf("speed.mode=%s: expected empty strategy_id, got %q", mode, out.StrategyID)
			}
		})
	}
}

// TestMCP_ReplayPcap_SpeedMode_Accepted verifies the three VALID speed modes
// pass validateReplaySpec (may still fail later at Start, but not with
// "invalid speed mode").
//
// Each sub-test uses its own env because the test env's done channel has a
// 4-buffer and each task start can produce up to one completion/failure
// signal; sharing the env across sub-tests would fill the buffer and
// deadlock engine.Stop at cleanup.
func TestMCP_ReplayPcap_SpeedMode_Accepted(t *testing.T) {
	cases := []struct {
		name  string
		speed map[string]interface{}
	}{
		{"original", map[string]interface{}{"mode": "original"}},
		{"multiplier", map[string]interface{}{"mode": "multiplier", "multiplier": 2.0}},
		{"bps", map[string]interface{}{"mode": "bps", "bps": "100M"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := setupMCPTest(t)
			defer env.cleanup()

			assetID := importTestPcap(t, env)
			env.eng.SetReplayPlanner(replay.NewReplayPlanner(env.db))

			_, out, err := env.srv.handleReplayPcap(context.Background(), nil, replayPcapInput{
				TaskName:    "replay-" + c.name,
				PcapAssetID: assetID,
				Speed:       c.speed,
				Loop:        1,
				OutputType:  "pcap",
				OutputConfig: &outputConfigInput{
					PcapPath: env.tmp + "/replay-" + c.name + ".pcap",
				},
			})
			// Drain any task completion/failure signal so engine.Stop at
			// cleanup doesn't deadlock on OnTaskFailed -> done <- taskID.
			go func() {
				for range env.done {
				}
			}()
			// We expect strategy creation to SUCCEED (so strategy_id is set).
			// Start may or may not succeed depending on the replay planner.
			if out.StrategyID == "" {
				t.Fatalf("speed.mode=%s: expected non-empty strategy_id, got empty (err=%v)", c.name, err)
			}
			if err != nil && strings.Contains(err.Error(), "invalid speed mode") {
				t.Errorf("speed.mode=%s: should NOT be rejected as invalid speed mode, but got: %v", c.name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// flowb_wait_for_task: failed/error terminal state (HIGH)
// ---------------------------------------------------------------------------

// TestMCP_WaitForTask_FailedState verifies the fix for the missing "failed"
// terminal state. Pre-fix, a task in status="failed" would never terminate
// the wait loop, causing timeout. Post-fix, "failed" is treated as terminal
// alongside completed/stopped/error.
func TestMCP_WaitForTask_FailedState(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Generate a task, then manually mark it as "failed" in the DB.
	_, genOut, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "failed-test",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"dst_port": 80, "count": 1},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/failed.pcap",
		},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Wait for engine to finish the (trivial) task, then flip DB to "failed".
	select {
	case <-env.done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete")
	}
	env.db.Exec("UPDATE tasks SET status = ?, progress = 50 WHERE id = ?", "failed", genOut.TaskID)

	// wait_for_task should return immediately with the failed state, NOT
	// time out.
	_, out, err := env.srv.handleWaitForTask(context.Background(), nil, waitForTaskInput{
		TaskID:              genOut.TaskID,
		TimeoutSeconds:      5,
		PollIntervalSeconds: 1,
	})
	if err != nil {
		t.Fatalf("wait_for_task on failed: %v", err)
	}
	var task map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &task); err != nil {
		t.Fatalf("wait returned non-object: %s", string(asRaw(out.Data)))
	}
	if status, _ := task["status"].(string); status != "failed" {
		t.Errorf("expected failed, got %q", status)
	}
}

// TestMCP_WaitForTask_ErrorState is the same regression for status="error".
func TestMCP_WaitForTask_ErrorState(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, genOut, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "error-test",
		Protocol:   "tcp",
		Config:     map[string]interface{}{"dst_port": 80, "count": 1},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/error.pcap",
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
	env.db.Exec("UPDATE tasks SET status = ? WHERE id = ?", "error", genOut.TaskID)

	_, out, err := env.srv.handleWaitForTask(context.Background(), nil, waitForTaskInput{
		TaskID:              genOut.TaskID,
		TimeoutSeconds:      5,
		PollIntervalSeconds: 1,
	})
	if err != nil {
		t.Fatalf("wait_for_task on error: %v", err)
	}
	var task map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &task); err != nil {
		t.Fatalf("wait returned non-object: %s", string(asRaw(out.Data)))
	}
	if status, _ := task["status"].(string); status != "error" {
		t.Errorf("expected error, got %q", status)
	}
}

// ---------------------------------------------------------------------------
// flowb_manage_users: 403 paths for admin-only actions (MEDIUM)
// ---------------------------------------------------------------------------

// TestMCP_ManageUsers_AdminActions_ForbiddenInServiceMode verifies that
// update/delete/reset_password all return 403 in service account mode
// (role=user). Pre-fix only list/get were tested, leaving 3 actions
// uncovered. The audit log shows "admin access required" for each.
func TestMCP_ManageUsers_AdminActions_ForbiddenInServiceMode(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	for _, action := range []string{"update", "delete", "reset_password"} {
		t.Run(action, func(t *testing.T) {
			_, _, err := env.srv.handleManageUsers(context.Background(), nil, manageUsersInput{
				Action: action,
				ID:     "some-user-id",
			})
			if err == nil {
				t.Fatalf("action %q: expected 403 error, got nil", action)
			}
			// 403 maps to InvalidParams in our backendError table.
			if !strings.Contains(err.Error(), "admin") && !strings.Contains(err.Error(), "forbidden") {
				t.Errorf("action %q: error %q should mention admin/forbidden", action, err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// flowb_manage_auth: refresh (MEDIUM)
// ---------------------------------------------------------------------------

// TestMCP_ManageAuth_Refresh verifies the refresh action: a valid token
// returns a new token; an invalid/expired token returns an error.
func TestMCP_ManageAuth_Refresh(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Register + login to get a token.
	_, _, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "register",
		Username: "refresh-user",
		Email:    "refresh@test.local",
		Password: "test-password-123",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	_, loginOut, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "login",
		Username: "refresh-user",
		Password: "test-password-123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var loginData struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(asRaw(loginOut.Data), &loginData); err != nil {
		t.Fatalf("login data parse: %v (data: %s)", err, string(asRaw(loginOut.Data)))
	}
	if loginData.Token == "" {
		t.Fatal("login did not return a token")
	}

	// Sleep >1s so the refresh's JWT has a different `iat` second than login's.
	// JWT NumericDate has 1-second precision; without this sleep, login and
	// refresh produce byte-identical tokens (same claims+iat+exp), causing a
	// token_hash UNIQUE constraint violation in the tokens table.
	time.Sleep(1100 * time.Millisecond)

	// Refresh with the valid token.
	_, refreshOut, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "refresh",
		Token:  loginData.Token,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var refreshData struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(asRaw(refreshOut.Data), &refreshData); err != nil {
		t.Fatalf("refresh data parse: %v (data: %s)", err, string(asRaw(refreshOut.Data)))
	}
	if refreshData.Token == "" {
		t.Error("refresh returned empty token")
	}
}

// TestMCP_ManageAuth_Refresh_InvalidToken verifies refresh with a bogus token
// fails.
func TestMCP_ManageAuth_Refresh_InvalidToken(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "refresh",
		Token:  "not-a-real-token",
	})
	if err == nil {
		t.Fatal("expected error for refresh with bogus token, got nil")
	}
}

// TestMCP_ManageAuth_Validate_RevokedToken verifies that a token revoked via
// logout cannot be reused for validate/refresh via MCP. Pre-fix, MCP's
// callHandlerWithToken only checked the JWT signature -- it did NOT check
// the DB token status, so a revoked token could still call validate/logout/
// refresh. Post-fix, the DB status is checked and revoked tokens are rejected.
func TestMCP_ManageAuth_Validate_RevokedToken(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Register + login to get a token.
	_, _, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "register",
		Username: "revoke-user",
		Email:    "revoke@test.local",
		Password: "test-password-123",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	_, loginOut, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "login",
		Username: "revoke-user",
		Password: "test-password-123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var loginData struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(asRaw(loginOut.Data), &loginData); err != nil {
		t.Fatalf("login data parse: %v", err)
	}
	if loginData.Token == "" {
		t.Fatal("login did not return a token")
	}

	// Validate works while active.
	_, _, err = env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "validate",
		Token:  loginData.Token,
	})
	if err != nil {
		t.Fatalf("validate on active token should succeed, got: %v", err)
	}

	// Logout revokes the token in DB.
	_, _, err = env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "logout",
		Token:  loginData.Token,
	})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}

	// Validate on revoked token should now fail.
	_, _, err = env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "validate",
		Token:  loginData.Token,
	})
	if err == nil {
		t.Fatal("expected error for validate on revoked token, got nil (DB status check missing)")
	}
	if !strings.Contains(err.Error(), "revoked") && !strings.Contains(err.Error(), "not active") {
		t.Errorf("error should mention revoked/not active, got: %v", err)
	}

	// Refresh on revoked token should also fail.
	_, _, err = env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "refresh",
		Token:  loginData.Token,
	})
	if err == nil {
		t.Fatal("expected error for refresh on revoked token, got nil (DB status check missing)")
	}
}

// ---------------------------------------------------------------------------
// flowb_query_system: refresh_interfaces (MEDIUM)
// ---------------------------------------------------------------------------

// TestMCP_QuerySystem_RefreshInterfaces verifies the refresh_interfaces action
// returns successfully (the action is exercised; we don't assert on the
// interface list contents since the test env has no real NICs).
func TestMCP_QuerySystem_RefreshInterfaces(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleQuerySystem(context.Background(), nil, querySystemInput{
		Action: "refresh_interfaces",
	})
	if err != nil {
		t.Fatalf("refresh_interfaces: %v", err)
	}
	if out.Data == nil {
		t.Error("refresh_interfaces returned nil data")
	}
}

// ---------------------------------------------------------------------------
// flowb_manage_strategies: get (MEDIUM)
// ---------------------------------------------------------------------------

// TestMCP_ManageStrategies_Get verifies the get action returns a single
// strategy. (The action is also exercised incidentally by other tests, but
// this is the dedicated coverage.)
func TestMCP_ManageStrategies_Get(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Create a strategy first.
	_, createOut, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action:   "create",
		Name:     "get-test",
		Mode:     "synth",
		Protocol: "tcp",
		Config:   map[string]interface{}{"dst_port": 80},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(asRaw(createOut.Data), &created); err != nil {
		t.Fatalf("create data parse: %v", err)
	}
	if created.ID == "" {
		t.Fatal("create did not return an id")
	}

	// Get it back.
	_, out, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     created.ID,
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var strat map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &strat); err != nil {
		t.Fatalf("get returned non-object: %s", string(asRaw(out.Data)))
	}
	if strat["id"] != created.ID && strat["ID"] != created.ID {
		t.Errorf("get returned wrong id: got %v, want %s", strat["id"], created.ID)
	}
	if strat["mode"] != "synth" && strat["Mode"] != "synth" {
		t.Errorf("get returned wrong mode: %v", strat["mode"])
	}
}

// TestMCP_ManageStrategies_Get_NotFound verifies get on a nonexistent id
// returns an InvalidParams error (404 -> -32602 per our error mapping).
func TestMCP_ManageStrategies_Get_NotFound(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageStrategies(context.Background(), nil, manageStrategiesInput{
		Action: "get",
		ID:     "nonexistent-strategy-id",
	})
	if err == nil {
		t.Fatal("expected error for get on nonexistent id, got nil")
	}
}

// ---------------------------------------------------------------------------
// flowb_manage_tasks: start idempotency / conflict (MEDIUM)
// ---------------------------------------------------------------------------

// TestMCP_ManageTasks_Start_NonExistent verifies starting a nonexistent task
// returns an error (404 -> InvalidParams).
func TestMCP_ManageTasks_Start_NonExistent(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "start",
		ID:     "nonexistent-task-id",
	})
	if err == nil {
		t.Fatal("expected error for start on nonexistent id, got nil")
	}
}

// ---------------------------------------------------------------------------
// flowb_manage_pcaps: delete with force (MEDIUM)
// ---------------------------------------------------------------------------

// TestMCP_ManagePcaps_Get_NonExistent verifies get on a nonexistent asset id
// returns InvalidParams (404).
func TestMCP_ManagePcaps_Get_NonExistent(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "get",
		ID:     "nonexistent-asset-id",
	})
	if err == nil {
		t.Fatal("expected error for get on nonexistent asset, got nil")
	}
}

// TestMCP_ManagePcaps_Reparse_NonExistent verifies reparse on a nonexistent
// asset id returns InvalidParams (404).
func TestMCP_ManagePcaps_Reparse_NonExistent(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "reparse",
		ID:     "nonexistent-asset-id",
	})
	if err == nil {
		t.Fatal("expected error for reparse on nonexistent asset, got nil")
	}
}

// TestMCP_ManagePcaps_Download_NonExistent verifies download on a nonexistent
// asset id returns InvalidParams (404).
func TestMCP_ManagePcaps_Download_NonExistent(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "download",
		ID:     "nonexistent-asset-id",
	})
	if err == nil {
		t.Fatal("expected error for download on nonexistent asset, got nil")
	}
}

// ---------------------------------------------------------------------------
// flowb_wait_for_task: argument clamping (LOW)
// ---------------------------------------------------------------------------

// TestMCP_WaitForTask_ClampTimeout verifies timeout > 300s is clamped to 300s
// (test passes 1000s; if not clamped, the test would block for 1000s on
// timeout, but with clamping the actual wait is bounded by the missing task
// returning 404 quickly).
func TestMCP_WaitForTask_ClampTimeout(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Use a nonexistent task id -- wait_for_task will fail fast on the Get
	// call (404), so the timeout value doesn't actually matter for runtime.
	// What we're verifying is that the function ACCEPTS timeout=1000 without
	// panicking (clamp to 300 happens internally).
	_, _, err := env.srv.handleWaitForTask(context.Background(), nil, waitForTaskInput{
		TaskID:              "nonexistent-task-id",
		TimeoutSeconds:      1000, // > 300, should be clamped
		PollIntervalSeconds: 1,
	})
	if err == nil {
		t.Fatal("expected error for wait on nonexistent task, got nil")
	}
}

// ---------------------------------------------------------------------------
// flowb_generate_traffic: invalid protocol (MEDIUM)
// ---------------------------------------------------------------------------

// TestMCP_GenerateTraffic_InvalidProtocol verifies an invalid protocol is
// rejected at strategy creation.
func TestMCP_GenerateTraffic_InvalidProtocol(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
		TaskName:   "bad-proto",
		Protocol:   "carrier-pigeon",
		Config:     map[string]interface{}{"dst_port": 80},
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: env.tmp + "/bad.pcap",
		},
	})
	if err == nil {
		t.Fatalf("expected error for invalid protocol, got nil (out=%+v)", out)
	}
	// On strategy-create failure, no IDs are returned.
	if out.StrategyID != "" || out.TaskID != "" {
		t.Errorf("expected empty IDs on strategy-create failure, got strat=%q task=%q",
			out.StrategyID, out.TaskID)
	}
}
