package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// TokenValidator interface for checking token status
type TokenValidator interface {
	IsTokenRevoked(tokenHash string) (bool, error)
}

// DBTokenValidator checks token status in database
type DBTokenValidator struct {
	db *gorm.DB
}

// NewDBTokenValidator creates a new database token validator
func NewDBTokenValidator(db *gorm.DB) *DBTokenValidator {
	return &DBTokenValidator{db: db}
}

// IsTokenRevoked checks if a token is revoked in the database
func (v *DBTokenValidator) IsTokenRevoked(tokenHash string) (bool, error) {
	var status string
	err := v.db.Table("tokens").Select("status").Where("token_hash = ?", tokenHash).Scan(&status).Error
	if err == gorm.ErrRecordNotFound {
		return true, nil // Token not in DB = revoked/not issued by us
	}
	if err != nil {
		return false, err
	}
	return status != "active", nil
}

// AuthMiddleware returns an authentication middleware.
func AuthMiddleware(jwtManager *JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    401,
				"message": "missing authorization header",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    401,
				"message": "invalid authorization header format",
			})
			return
		}

		claims, err := jwtManager.ValidateToken(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    401,
				"message": "invalid or expired token",
			})
			return
		}

		// Store claims in context
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("roles", claims.Roles)
		c.Set("token", parts[1]) // Store raw token for later revocation check

		c.Next()
	}
}

// AuthMiddlewareWithDB returns an authentication middleware that also checks token revocation.
func AuthMiddlewareWithDB(jwtManager *JWTManager, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    401,
				"message": "missing authorization header",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    401,
				"message": "invalid authorization header format",
			})
			return
		}

		claims, err := jwtManager.ValidateToken(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    401,
				"message": "invalid or expired token",
			})
			return
		}

		// Check if token is revoked in database
		tokenHash := hashToken(parts[1])
		var tokenRecord struct {
			Status    string
			ExpiresAt time.Time
		}
		err = db.Table("tokens").Select("status, expires_at").Where("token_hash = ?", tokenHash).Scan(&tokenRecord).Error
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    401,
				"message": "token not recognized",
			})
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(500, gin.H{
				"code":    500,
				"message": "failed to validate token",
			})
			return
		}

		if tokenRecord.Status != "active" {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    401,
				"message": "token has been revoked",
			})
			return
		}

		if time.Now().After(tokenRecord.ExpiresAt) {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    401,
				"message": "token has expired",
			})
			return
		}

		// Store claims in context
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("roles", claims.Roles)

		c.Next()
	}
}

// hashToken creates a SHA256 hash of the token
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// RBACMiddleware returns a role-based access control middleware.
func RBACMiddleware(rbac *RBAC, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesVal, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(403, gin.H{
				"code":    403,
				"message": "no roles found",
			})
			return
		}

		roles, ok := rolesVal.([]string)
		if !ok {
			c.AbortWithStatusJSON(403, gin.H{
				"code":    403,
				"message": "invalid roles",
			})
			return
		}

		if !rbac.CheckAccess(roles, permission) {
			c.AbortWithStatusJSON(403, gin.H{
				"code":    403,
				"message": "permission denied",
			})
			return
		}

		c.Next()
	}
}

// OptionalAuth returns an optional authentication middleware.
func OptionalAuth(jwtManager *JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		claims, err := jwtManager.ValidateToken(parts[1])
		if err == nil {
			c.Set("userID", claims.UserID)
			c.Set("username", claims.Username)
			c.Set("roles", claims.Roles)
		}

		c.Next()
	}
}

// GetUserID returns the user ID from context.
func GetUserID(c *gin.Context) string {
	if userID, exists := c.Get("userID"); exists {
		return userID.(string)
	}
	return ""
}

// GetUsername returns the username from context.
func GetUsername(c *gin.Context) string {
	if username, exists := c.Get("username"); exists {
		return username.(string)
	}
	return ""
}

// GetRoles returns the roles from context.
func GetRoles(c *gin.Context) []string {
	if roles, exists := c.Get("roles"); exists {
		return roles.([]string)
	}
	return nil
}

// IsAdmin checks if the user has admin role.
func IsAdmin(c *gin.Context) bool {
	roles := GetRoles(c)
	for _, role := range roles {
		if role == "admin" {
			return true
		}
	}
	return false
}
