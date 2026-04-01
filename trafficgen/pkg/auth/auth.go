// Package auth provides authentication and authorization.
package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// JWTManager manages JWT tokens.
type JWTManager struct {
	secret    []byte
	issuer    string
	expiresIn time.Duration
}

// Claims represents JWT claims.
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// NewJWTManager creates a new JWT manager.
func NewJWTManager(secret, issuer string, expiresIn time.Duration) *JWTManager {
	return &JWTManager{
		secret:    []byte(secret),
		issuer:    issuer,
		expiresIn: expiresIn,
	}
}

// GenerateToken generates a JWT token.
func (m *JWTManager) GenerateToken(userID, username string, roles []string) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.expiresIn)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

// ValidateToken validates a JWT token.
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RefreshToken refreshes a token.
func (m *JWTManager) RefreshToken(tokenString string) (string, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	return m.GenerateToken(claims.UserID, claims.Username, claims.Roles)
}

// HashPassword hashes a password.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword checks if a password matches a hash.
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// RBAC manages role-based access control.
type RBAC struct {
	roles       map[string][]string
	permissions map[string][]string
}

// NewRBAC creates a new RBAC manager.
func NewRBAC() *RBAC {
	return &RBAC{
		roles:       make(map[string][]string),
		permissions: make(map[string][]string),
	}
}

// AddRole adds a role with permissions.
func (r *RBAC) AddRole(role string, permissions []string) {
	r.roles[role] = permissions
}

// AddPermission adds a permission to a role.
func (r *RBAC) AddPermission(role, permission string) {
	r.roles[role] = append(r.roles[role], permission)
}

// HasPermission checks if a role has a permission.
func (r *RBAC) HasPermission(role, permission string) bool {
	permissions, ok := r.roles[role]
	if !ok {
		return false
	}

	for _, p := range permissions {
		if p == permission || p == "*" {
			return true
		}
	}

	return false
}

// HasAnyPermission checks if a role has any of the permissions.
func (r *RBAC) HasAnyPermission(role string, permissions []string) bool {
	for _, p := range permissions {
		if r.HasPermission(role, p) {
			return true
		}
	}
	return false
}

// CheckAccess checks if a user with roles has access to a resource.
func (r *RBAC) CheckAccess(roles []string, permission string) bool {
	for _, role := range roles {
		if r.HasPermission(role, permission) {
			return true
		}
	}
	return false
}

// Default roles and permissions.
var DefaultRBAC = NewRBAC()

func init() {
	// Admin role - full access
	DefaultRBAC.AddRole("admin", []string{"*"})

	// User role - limited access
	DefaultRBAC.AddRole("user", []string{
		"task:read",
		"task:create",
		"task:start",
		"task:stop",
		"strategy:read",
		"interface:read",
	})

	// Viewer role - read only
	DefaultRBAC.AddRole("viewer", []string{
		"task:read",
		"strategy:read",
		"interface:read",
		"system:read",
	})
}
