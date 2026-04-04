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

	// Create user (always as "user" role, admin can only be created via config)
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

// GetProfile returns the current user's profile.
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var user storage.UserModel
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "user not found")
			return
		}
		InternalError(c, "failed to query user")
		return
	}

	Success(c, map[string]interface{}{
		"user_id":       user.ID,
		"username":      user.Username,
		"email":         user.Email,
		"role":          user.Role,
		"enabled":       user.Enabled,
		"last_login_at": user.LastLoginAt,
		"created_at":    user.CreatedAt,
	})
}

// UpdateProfileRequest represents a profile update request.
type UpdateProfileRequest struct {
	Email    string `json:"email" binding:"omitempty,email"`
	Password string `json:"password" binding:"omitempty,min=6,max=128"`
}

// UpdateProfile updates the current user's profile.
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var user storage.UserModel
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "user not found")
			return
		}
		InternalError(c, "failed to query user")
		return
	}

	// Check if user is admin (admin cannot be modified via API)
	if user.Role == "admin" {
		Forbidden(c, "admin account cannot be modified via API")
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	updates := map[string]interface{}{}

	if req.Email != "" && req.Email != user.Email {
		// Check if email already exists
		var existingUser storage.UserModel
		if err := h.db.Where("email = ? AND id != ?", req.Email, userID).First(&existingUser).Error; err == nil {
			BadRequest(c, "email already exists")
			return
		}
		updates["email"] = req.Email
	}

	if req.Password != "" {
		passwordHash, err := auth.HashPassword(req.Password)
		if err != nil {
			InternalError(c, "failed to hash password")
			return
		}
		updates["password_hash"] = passwordHash
	}

	if len(updates) > 0 {
		if err := h.db.Model(&user).Updates(updates).Error; err != nil {
			InternalError(c, "failed to update profile")
			return
		}
	}

	SuccessWithMessage(c, "profile updated", nil)
}

// DeleteProfile deletes the current user's account.
func (h *AuthHandler) DeleteProfile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var user storage.UserModel
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "user not found")
			return
		}
		InternalError(c, "failed to query user")
		return
	}

	// Check if user is admin (admin cannot be deleted via API)
	if user.Role == "admin" {
		Forbidden(c, "admin account cannot be deleted via API")
		return
	}

	// Revoke all tokens for this user
	h.db.Model(&storage.TokenModel{}).Where("user_id = ?", userID).Update("status", "revoked")

	// Delete user
	if err := h.db.Delete(&user).Error; err != nil {
		InternalError(c, "failed to delete account")
		return
	}

	SuccessWithMessage(c, "account deleted", nil)
}
