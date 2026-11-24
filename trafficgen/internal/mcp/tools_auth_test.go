package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// flowb_manage_auth - 5 actions
// ---------------------------------------------------------------------------

func TestMCP_ManageAuth_RegisterAndLogin(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Register a new user via MCP
	_, out, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "register",
		Username: "alice",
		Password: "alice-password-123",
		Email:    "alice@test.local",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var regData map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &regData); err != nil {
		t.Fatalf("register returned non-object: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	if regData["username"] != "alice" {
		t.Errorf("register.username: got %v, want alice", regData["username"])
	}

	// Login with the registered user
	_, out2, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "login",
		Username: "alice",
		Password: "alice-password-123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var loginData map[string]interface{}
	if err := json.Unmarshal(asRaw(out2.Data), &loginData); err != nil {
		t.Fatalf("login returned non-object: %s (err: %v)", string(asRaw(out2.Data)), err)
	}
	token, ok := loginData["token"].(string)
	if !ok || token == "" {
		t.Fatalf("login did not return token: %s", string(asRaw(out2.Data)))
	}
	if loginData["username"] != "alice" {
		t.Errorf("login.username: got %v, want alice", loginData["username"])
	}
}

func TestMCP_ManageAuth_LoginWrongPassword(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Register
	_, _, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "register",
		Username: "bob",
		Password: "bob-password-123",
		Email:    "bob@test.local",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Login with wrong password -> error
	_, _, err = env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "login",
		Username: "bob",
		Password: "wrong-password-123",
	})
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestMCP_ManageAuth_ValidateToken(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Register + login to get a token
	_, _, _ = env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "register",
		Username: "carol",
		Password: "carol-password-123",
		Email:    "carol@test.local",
	})
	_, out, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "login",
		Username: "carol",
		Password: "carol-password-123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var loginData map[string]interface{}
	json.Unmarshal(asRaw(out.Data), &loginData)
	token := loginData["token"].(string)

	// Validate the token
	_, out2, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "validate",
		Token:  token,
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	var validateData map[string]interface{}
	if err := json.Unmarshal(asRaw(out2.Data), &validateData); err != nil {
		t.Fatalf("validate returned non-object: %s (err: %v)", string(asRaw(out2.Data)), err)
	}
	if validateData["valid"] != true {
		t.Errorf("validate.valid: got %v, want true", validateData["valid"])
	}
	if validateData["username"] != "carol" {
		t.Errorf("validate.username: got %v, want carol", validateData["username"])
	}
}

func TestMCP_ManageAuth_ValidateToken_Invalid(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Validate a bogus token -> error (JWT parse fails in MCP before handler)
	_, _, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "validate",
		Token:  "not.a.valid.jwt",
	})
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

func TestMCP_ManageAuth_ValidateToken_Empty(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "validate",
		Token:  "",
	})
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestMCP_ManageAuth_Logout(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	// Register + login
	_, _, _ = env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "register",
		Username: "dave",
		Password: "dave-password-123",
		Email:    "dave@test.local",
	})
	_, out, _ := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action:   "login",
		Username: "dave",
		Password: "dave-password-123",
	})
	var loginData map[string]interface{}
	json.Unmarshal(asRaw(out.Data), &loginData)
	token := loginData["token"].(string)

	// Logout
	_, _, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "logout",
		Token:  token,
	})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}

	// Validate after logout -> should fail (token revoked in DB)
	_, _, err = env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "validate",
		Token:  token,
	})
	if err == nil {
		t.Fatal("expected error when validating revoked token, got nil")
	}
}

func TestMCP_ManageAuth_InvalidAction(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManageAuth(context.Background(), nil, manageAuthInput{
		Action: "bogus",
	})
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}

// TestMCP_ManageProfile_DeleteIgnoresOrRejectsPassword 覆盖 delete 分支：
// 描述曾宣称 password 是"删除确认"，但后端 DeleteProfile 从来不读它——传了
// 也删、不传也删，调用方以为有安全兜底。现在带密码的 delete 被明确拒绝，
// 不带密码的 delete 真的删号。
func TestMCP_ManageProfile_DeleteIgnoresOrRejectsPassword(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	if _, _, err := env.srv.handleManageProfile(context.Background(), nil, manageProfileInput{
		Action:   "delete",
		Password: "whatever",
	}); err == nil {
		t.Fatalf("delete with a password was accepted; it must be rejected — " +
			"the password is not a confirmation, the account is removed immediately")
	}

	// 账号仍在（上一步是拒绝，不是删除）。
	if _, _, err := env.srv.handleManageProfile(context.Background(), nil, manageProfileInput{Action: "get"}); err != nil {
		t.Fatalf("account gone after a rejected delete: %v", err)
	}

	// 不带密码才真的删。
	if _, _, err := env.srv.handleManageProfile(context.Background(), nil, manageProfileInput{Action: "delete"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := env.srv.handleManageProfile(context.Background(), nil, manageProfileInput{Action: "get"}); err == nil {
		t.Fatalf("account still readable after a successful delete")
	}
}
