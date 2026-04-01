package auth

import (
	"testing"
	"time"
)

func TestJWTManager_GenerateAndValidate(t *testing.T) {
	manager := NewJWTManager("test-secret", "trafficgen", time.Hour)

	token, err := manager.GenerateToken("user-1", "testuser", []string{"admin"})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.UserID != "user-1" {
		t.Errorf("UserID = %s, want user-1", claims.UserID)
	}
	if claims.Username != "testuser" {
		t.Errorf("Username = %s, want testuser", claims.Username)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Errorf("Roles = %v, want [admin]", claims.Roles)
	}
}

func TestJWTManager_InvalidToken(t *testing.T) {
	manager := NewJWTManager("test-secret", "trafficgen", time.Hour)

	// Test invalid token
	_, err := manager.ValidateToken("invalid-token")
	if err == nil {
		t.Error("ValidateToken() should fail for invalid token")
	}

	// Test token signed with different secret
	otherManager := NewJWTManager("other-secret", "trafficgen", time.Hour)
	token, _ := otherManager.GenerateToken("user-1", "testuser", []string{"admin"})

	_, err = manager.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should fail for token signed with different secret")
	}
}

func TestJWTManager_RefreshToken(t *testing.T) {
	manager := NewJWTManager("test-secret", "trafficgen", time.Hour)

	token, _ := manager.GenerateToken("user-1", "testuser", []string{"admin"})
	newToken, err := manager.RefreshToken(token)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if newToken == "" {
		t.Error("New token should not be empty")
	}

	// Validate new token
	claims, _ := manager.ValidateToken(newToken)
	if claims.UserID != "user-1" {
		t.Errorf("UserID = %s, want user-1", claims.UserID)
	}
}

func TestHashPassword(t *testing.T) {
	password := "testpassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == "" {
		t.Error("Hash should not be empty")
	}

	if hash == password {
		t.Error("Hash should not equal password")
	}
}

func TestCheckPassword(t *testing.T) {
	password := "testpassword"
	hash, _ := HashPassword(password)

	if !CheckPassword(password, hash) {
		t.Error("CheckPassword() should return true for correct password")
	}

	if CheckPassword("wrongpassword", hash) {
		t.Error("CheckPassword() should return false for wrong password")
	}
}

func TestRBAC(t *testing.T) {
	rbac := NewRBAC()
	rbac.AddRole("admin", []string{"*"})
	rbac.AddRole("user", []string{"task:read", "task:create"})
	rbac.AddRole("viewer", []string{"task:read"})

	tests := []struct {
		role       string
		permission string
		want       bool
	}{
		{"admin", "task:delete", true},
		{"admin", "anything", true},
		{"user", "task:read", true},
		{"user", "task:create", true},
		{"user", "task:delete", false},
		{"viewer", "task:read", true},
		{"viewer", "task:create", false},
		{"unknown", "task:read", false},
	}

	for _, tt := range tests {
		t.Run(tt.role+"_"+tt.permission, func(t *testing.T) {
			got := rbac.HasPermission(tt.role, tt.permission)
			if got != tt.want {
				t.Errorf("HasPermission(%s, %s) = %v, want %v", tt.role, tt.permission, got, tt.want)
			}
		})
	}
}

func TestRBAC_CheckAccess(t *testing.T) {
	rbac := NewRBAC()
	rbac.AddRole("admin", []string{"*"})
	rbac.AddRole("user", []string{"task:read"})

	// Admin should have access
	if !rbac.CheckAccess([]string{"admin"}, "task:delete") {
		t.Error("Admin should have access to any permission")
	}

	// User should have access to task:read
	if !rbac.CheckAccess([]string{"user"}, "task:read") {
		t.Error("User should have access to task:read")
	}

	// User should not have access to task:delete
	if rbac.CheckAccess([]string{"user"}, "task:delete") {
		t.Error("User should not have access to task:delete")
	}

	// Multiple roles - one has permission
	if !rbac.CheckAccess([]string{"user", "admin"}, "task:delete") {
		t.Error("Should have access if any role has permission")
	}
}

func TestDefaultRBAC(t *testing.T) {
	// Test default roles
	if !DefaultRBAC.HasPermission("admin", "anything") {
		t.Error("Admin should have all permissions")
	}

	if !DefaultRBAC.HasPermission("user", "task:read") {
		t.Error("User should have task:read permission")
	}

	if DefaultRBAC.HasPermission("user", "task:delete") {
		t.Error("User should not have task:delete permission")
	}

	if !DefaultRBAC.HasPermission("viewer", "system:read") {
		t.Error("Viewer should have system:read permission")
	}
}
