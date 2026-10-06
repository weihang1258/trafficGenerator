package rest

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"gorm.io/gorm"
)

// UserHandler handles user management requests (admin only).
type UserHandler struct {
	db *storage.DB
}

// NewUserHandler creates a new user handler.
func NewUserHandler(db *storage.DB) *UserHandler {
	return &UserHandler{db: db}
}

// UserResponse represents a user in API responses.
type UserResponse struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	LastLogin int64  `json:"last_login"`
}

// List lists all users (admin only).
func (h *UserHandler) List(c *gin.Context) {
	if !auth.IsAdmin(c) {
		Forbidden(c, "admin access required")
		return
	}

	var users []storage.UserModel
	if err := h.db.Find(&users).Error; err != nil {
		InternalError(c, "failed to list users: "+err.Error())
		return
	}

	result := make([]UserResponse, len(users))
	for i, u := range users {
		result[i] = toUserResponse(u)
	}

	Success(c, result)
}

// Get gets a single user by ID (admin only).
func (h *UserHandler) Get(c *gin.Context) {
	if !auth.IsAdmin(c) {
		Forbidden(c, "admin access required")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing user id")
		return
	}

	var user storage.UserModel
	if err := h.db.Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "user not found")
			return
		}
		InternalError(c, "failed to get user: "+err.Error())
		return
	}

	Success(c, toUserResponse(user))
}

// toUserResponse converts a UserModel to a UserResponse.
func toUserResponse(u storage.UserModel) UserResponse {
	lastLogin := int64(0)
	if u.LastLoginAt != nil {
		lastLogin = u.LastLoginAt.Unix()
	}
	return UserResponse{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		Role:      u.Role,
		Enabled:   u.Enabled,
		CreatedAt: u.CreatedAt.Unix(),
		UpdatedAt: u.UpdatedAt.Unix(),
		LastLogin: lastLogin,
	}
}

// Update updates a user (admin only).
func (h *UserHandler) Update(c *gin.Context) {
	if !auth.IsAdmin(c) {
		Forbidden(c, "admin access required")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing user id")
		return
	}

	var req struct {
		Role    string `json:"role"`
		Enabled *bool  `json:"enabled"`
		Email   string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	var user storage.UserModel
	if err := h.db.Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "user not found")
			return
		}
		InternalError(c, "failed to find user: "+err.Error())
		return
	}

	if req.Role != "" {
		validRoles := map[string]bool{"admin": true, "user": true, "guest": true}
		if !validRoles[req.Role] {
			BadRequest(c, "invalid role: must be admin, user, or guest")
			return
		}
		user.Role = req.Role
	}
	if req.Enabled != nil {
		user.Enabled = *req.Enabled
	}
	if req.Email != "" {
		user.Email = req.Email
	}

	if err := h.db.Save(&user).Error; err != nil {
		InternalError(c, "failed to update user: "+err.Error())
		return
	}

	SuccessWithMessage(c, "user updated", nil)
}

// Delete deletes a user (admin only).
func (h *UserHandler) Delete(c *gin.Context) {
	if !auth.IsAdmin(c) {
		Forbidden(c, "admin access required")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing user id")
		return
	}

	var user storage.UserModel
	if err := h.db.Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "user not found")
			return
		}
		InternalError(c, "failed to find user: "+err.Error())
		return
	}

	if user.Role == "admin" {
		BadRequest(c, "cannot delete admin user")
		return
	}

	if err := h.db.Delete(&user).Error; err != nil {
		InternalError(c, "failed to delete user: "+err.Error())
		return
	}

	SuccessWithMessage(c, "user deleted", map[string]interface{}{"id": id, "deleted": true})
}

// ResetPassword resets a user's password (admin only).
func (h *UserHandler) ResetPassword(c *gin.Context) {
	if !auth.IsAdmin(c) {
		Forbidden(c, "admin access required")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing user id")
		return
	}

	var user storage.UserModel
	if err := h.db.Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "user not found")
			return
		}
		InternalError(c, "failed to find user: "+err.Error())
		return
	}

	// Generate a random temporary password
	tmpBytes := make([]byte, 8)
	if _, err := rand.Read(tmpBytes); err != nil {
		InternalError(c, "failed to generate password")
		return
	}
	tmpPassword := hex.EncodeToString(tmpBytes)

	hashedPassword, err := auth.HashPassword(tmpPassword)
	if err != nil {
		InternalError(c, "failed to hash password")
		return
	}
	user.PasswordHash = hashedPassword

	if err := h.db.Save(&user).Error; err != nil {
		InternalError(c, "failed to reset password: "+err.Error())
		return
	}

	SuccessWithMessage(c, "password reset", map[string]string{
		"temporary_password": tmpPassword,
	})
}
