package rest

import (
	"crypto/md5"
	"encoding/hex"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"gorm.io/gorm"
)

// AuthHandler handles authentication requests.
type AuthHandler struct {
	db         *storage.DB
	jwtManager *auth.JWTManager
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(db *storage.DB, jwtManager *auth.JWTManager) *AuthHandler {
	return &AuthHandler{
		db:         db,
		jwtManager: jwtManager,
	}
}

// RegisterRequest represents a registration request.
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=64"`
	Password string `json:"password" binding:"required,min=6,max=128"`
	Email    string `json:"email" binding:"required,email"`
}

// LoginRequest represents a login request.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents a login response.
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
}

// Register handles user registration.
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Check if username already exists
	var existingUser storage.UserModel
	if err := h.db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		BadRequest(c, "username already exists")
		return
	}

	// Check if email already exists
	if err := h.db.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		BadRequest(c, "email already exists")
		return
	}

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		InternalError(c, "failed to hash password")
		return
	}

	// Create user
	user := &storage.UserModel{
		ID:           uuid.New().String(),
		Username:     req.Username,
		PasswordHash: passwordHash,
		Email:        req.Email,
		Role:         "user",
		Enabled:      true,
	}

	if err := h.db.Create(user).Error; err != nil {
		InternalError(c, "failed to create user: "+err.Error())
		return
	}

	Success(c, map[string]string{
		"user_id":  user.ID,
		"username": user.Username,
		"email":    user.Email,
	})
}

// Login handles user login.
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Find user
	var user storage.UserModel
	if err := h.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			Unauthorized(c, "invalid credentials")
			return
		}
		InternalError(c, "failed to query user")
		return
	}

	// Check if user is enabled
	if !user.Enabled {
		Unauthorized(c, "user is disabled")
		return
	}

	// Verify password
	if !auth.CheckPassword(req.Password, user.PasswordHash) {
		Unauthorized(c, "invalid credentials")
		return
	}

	// Generate JWT token
	token, err := h.jwtManager.GenerateToken(user.ID, user.Username, []string{user.Role})
	if err != nil {
		InternalError(c, "failed to generate token")
		return
	}

	// Store token in database for validation
	tokenHash := hashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)
	tokenRecord := &storage.TokenModel{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		Status:    "active",
	}

	if err := h.db.Create(tokenRecord).Error; err != nil {
		InternalError(c, "failed to store token")
		return
	}

	// Update last login time
	now := time.Now()
	h.db.Model(&user).Update("last_login_at", &now)

	Success(c, LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Unix(),
		UserID:    user.ID,
		Username:  user.Username,
	})
}

// ValidateToken handles token validation.
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		BadRequest(c, "missing authorization header")
		return
	}

	// Extract token
	tokenString := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		tokenString = authHeader[7:]
	} else {
		BadRequest(c, "invalid authorization header format")
		return
	}

	// Validate JWT
	claims, err := h.jwtManager.ValidateToken(tokenString)
	if err != nil {
		Unauthorized(c, "invalid or expired token")
		return
	}

	// Check token status in database
	tokenHash := hashToken(tokenString)
	var tokenRecord storage.TokenModel
	if err := h.db.Where("token_hash = ?", tokenHash).First(&tokenRecord).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			Unauthorized(c, "token not found")
			return
		}
		InternalError(c, "failed to query token")
		return
	}

	// Check if token is revoked
	if tokenRecord.Status != "active" {
		Unauthorized(c, "token is revoked")
		return
	}

	// Check if token is expired
	if time.Now().After(tokenRecord.ExpiresAt) {
		Unauthorized(c, "token is expired")
		return
	}

	Success(c, map[string]interface{}{
		"valid":    true,
		"user_id":  claims.UserID,
		"username": claims.Username,
		"roles":    claims.Roles,
	})
}

// Logout handles user logout.
func (h *AuthHandler) Logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		SuccessWithMessage(c, "logged out", nil)
		return
	}

	// Extract token
	tokenString := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		tokenString = authHeader[7:]
	}

	if tokenString != "" {
		// Revoke token in database
		tokenHash := hashToken(tokenString)
		h.db.Model(&storage.TokenModel{}).
			Where("token_hash = ?", tokenHash).
			Update("status", "revoked")
	}

	SuccessWithMessage(c, "logged out", nil)
}

// hashToken creates a hash of the token for storage.
func hashToken(token string) string {
	hash := md5.Sum([]byte(token))
	return hex.EncodeToString(hash[:])
}
