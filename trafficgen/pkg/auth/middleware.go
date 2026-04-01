package auth

import (
	"strings"

	"github.com/gin-gonic/gin"
)

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

		c.Next()
	}
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
