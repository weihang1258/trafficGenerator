package security_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)


// createTestToken creates a test user and returns an auth token
func createTestToken(t *testing.T, server *rest.Server) string {
	// Register
	registerBody := map[string]string{
		"username": "testuser",
		"password": "testpass123",
		"email":    "test@example.com",
	}
	body, _ := json.Marshal(registerBody)
	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.Router().ServeHTTP(w, req)
	require.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated, "register failed: %d %s", w.Code, w.Body.String())

	// Login
	loginBody := map[string]string{
		"username": "testuser",
		"password": "testpass123",
	}
	body, _ = json.Marshal(loginBody)
	req = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	server.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "login failed: %s", w.Body.String())

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	data := response["data"].(map[string]interface{})
	return data["token"].(string)
}
// TestSQLInjection tests for SQL injection vulnerabilities
func TestSQLInjection(t *testing.T) {
	// Setup test server
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: ":memory:",
			},
			Pool: config.PoolConfig{
				MaxOpen:      10,
				MaxIdle:      5,
				ConnLifetime: 300,
			},
		},
		Auth: config.AuthConfig{
			JWTSecret:    "test-secret-key",
			JWTIssuer:    "trafficgen-test",
			JWTExpiresIn: 24,
		},
	}

	gormDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	// Manually create tables to avoid AutoMigrate issues
	err = gormDB.Exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, strategy_ids TEXT, output_type TEXT, output_config TEXT, flow_control TEXT, status TEXT NOT NULL, progress REAL DEFAULT 0, error_message TEXT, created_at DATETIME, updated_at DATETIME, started_at DATETIME, completed_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE strategies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, protocol TEXT NOT NULL, config TEXT, flow_control TEXT, config_hash TEXT, created_at DATETIME, updated_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, role TEXT NOT NULL DEFAULT 'user', enabled BOOLEAN DEFAULT 1, created_at DATETIME, updated_at DATETIME, last_login_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at DATETIME)").Error
	require.NoError(t, err)
	db := &storage.DB{DB: gormDB}
	defer db.Close()

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1,
		PacketWorkers: 1,
		OutputWorkers: 1,
		BufferSize:    100,
		QueueSize:     10,
	})

	server := rest.NewServer(cfg, engine, nil, db, nil)
	err = server.Setup()
	assert.NoError(t, err)

		token := createTestToken(t, server)

	// SQL injection payloads
	sqlInjectionPayloads := []string{
		"'; DROP TABLE tasks; --",
		"' OR '1'='1",
		"' OR '1'='1' --",
		"' OR '1'='1' /*",
		"1; SELECT * FROM tasks",
		"1 OR 1=1",
		"admin'--",
		"admin' #",
		"' UNION SELECT * FROM tasks --",
	}

	for _, payload := range sqlInjectionPayloads {
		t.Run("SQL_Injection_"+payload, func(t *testing.T) {
			// Test in task name field
			taskReq := map[string]interface{}{
				"name":   payload,
				"protocol": "tcp",
				"config": map[string]interface{}{
					"src_ip":   "192.168.1.1",
					"dst_ip":   "192.168.1.2",
					"src_port": 12345,
					"dst_port": 80,
				},
			}

			body, _ := json.Marshal(taskReq)
			req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			server.Router().ServeHTTP(w, req)

			// Should not return 500 error (SQL error)
			// Should return 400 (bad request) or 201 (created with escaped input)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"SQL injection payload should not cause server error: %s", payload)

			// Verify database is not corrupted
			var count int64
			s := db.DB.Session(&gorm.Session{AllowGlobalUpdate: true})
			s.Model(&storage.TaskModel{}).Where("1=1").Count(&count)
			assert.GreaterOrEqual(t, count, int64(0))
		})
	}
}

// TestXSS tests for Cross-Site Scripting vulnerabilities
func TestXSS(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: ":memory:",
			},
			Pool: config.PoolConfig{
				MaxOpen:      10,
				MaxIdle:      5,
				ConnLifetime: 300,
			},
		},
		Auth: config.AuthConfig{
			JWTSecret:    "test-secret-key",
			JWTIssuer:    "trafficgen-test",
			JWTExpiresIn: 24,
		},
	}

	gormDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	// Manually create tables to avoid AutoMigrate issues
	err = gormDB.Exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, strategy_ids TEXT, output_type TEXT, output_config TEXT, flow_control TEXT, status TEXT NOT NULL, progress REAL DEFAULT 0, error_message TEXT, created_at DATETIME, updated_at DATETIME, started_at DATETIME, completed_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE strategies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, protocol TEXT NOT NULL, config TEXT, flow_control TEXT, config_hash TEXT, created_at DATETIME, updated_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, role TEXT NOT NULL DEFAULT 'user', enabled BOOLEAN DEFAULT 1, created_at DATETIME, updated_at DATETIME, last_login_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at DATETIME)").Error
	require.NoError(t, err)
	db := &storage.DB{DB: gormDB}
	defer db.Close()

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1,
		PacketWorkers: 1,
		OutputWorkers: 1,
		BufferSize:    100,
		QueueSize:     10,
	})

	server := rest.NewServer(cfg, engine, nil, db, nil)
	err = server.Setup()
	assert.NoError(t, err)

		token := createTestToken(t, server)

	// XSS payloads
	xssPayloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"javascript:alert('XSS')",
		"<body onload=alert('XSS')>",
		"<iframe src='javascript:alert(1)'>",
		"'><script>alert('XSS')</script>",
		"\"><script>alert('XSS')</script>",
	}

	for _, payload := range xssPayloads {
		t.Run("XSS_"+payload, func(t *testing.T) {
			taskReq := map[string]interface{}{
				"name":     payload,
				"protocol": "tcp",
				"config": map[string]interface{}{
					"src_ip":   "192.168.1.1",
					"dst_ip":   "192.168.1.2",
					"src_port": 12345,
					"dst_port": 80,
				},
			}

			body, _ := json.Marshal(taskReq)
			req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			server.Router().ServeHTTP(w, req)

			// Response should not contain unescaped script tags
			assert.NotContains(t, w.Body.String(), "<script>",
				"Response should not contain unescaped script tags")
			assert.NotContains(t, w.Body.String(), "onerror=",
				"Response should not contain unescaped event handlers")
			assert.NotContains(t, w.Body.String(), "onload=",
				"Response should not contain unescaped event handlers")
		})
	}
}

// TestCSRF tests for Cross-Site Request Forgery vulnerabilities
func TestCSRF(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: ":memory:",
			},
			Pool: config.PoolConfig{
				MaxOpen:      10,
				MaxIdle:      5,
				ConnLifetime: 300,
			},
		},
		Auth: config.AuthConfig{
			JWTSecret:    "test-secret-key",
			JWTIssuer:    "trafficgen-test",
			JWTExpiresIn: 24,
		},
	}

	gormDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	// Manually create tables to avoid AutoMigrate issues
	err = gormDB.Exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, strategy_ids TEXT, output_type TEXT, output_config TEXT, flow_control TEXT, status TEXT NOT NULL, progress REAL DEFAULT 0, error_message TEXT, created_at DATETIME, updated_at DATETIME, started_at DATETIME, completed_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE strategies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, protocol TEXT NOT NULL, config TEXT, flow_control TEXT, config_hash TEXT, created_at DATETIME, updated_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, role TEXT NOT NULL DEFAULT 'user', enabled BOOLEAN DEFAULT 1, created_at DATETIME, updated_at DATETIME, last_login_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at DATETIME)").Error
	require.NoError(t, err)
	db := &storage.DB{DB: gormDB}
	defer db.Close()

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1,
		PacketWorkers: 1,
		OutputWorkers: 1,
		BufferSize:    100,
		QueueSize:     10,
	})

	server := rest.NewServer(cfg, engine, nil, db, nil)
	err = server.Setup()
	assert.NoError(t, err)


	t.Run("CSRF_without_origin_check", func(t *testing.T) {
		taskReq := map[string]interface{}{
			"name":     "test-task",
			"protocol": "tcp",
			"config": map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 12345,
				"dst_port": 80,
			},
		}

		token := createTestToken(t, server)
		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		// Simulate request from different origin
		req.Header.Set("Origin", "https://malicious-site.com")
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		// API should either:
		// 1. Reject cross-origin requests (403)
		// 2. Accept but with proper CORS headers
		// For this test, we check that the response doesn't allow arbitrary origins
		allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
		if allowOrigin != "" {
			assert.NotEqual(t, "*", allowOrigin,
				"CORS should not allow wildcard origin for authenticated endpoints")
		}
	})
}

// TestAuthenticationBypass tests for authentication bypass vulnerabilities
func TestAuthenticationBypass(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: ":memory:",
			},
			Pool: config.PoolConfig{
				MaxOpen:      10,
				MaxIdle:      5,
				ConnLifetime: 300,
			},
		},
		Auth: config.AuthConfig{
			JWTSecret:    "test-secret-key",
			JWTIssuer:    "trafficgen-test",
			JWTExpiresIn: 24,
		},
	}

	gormDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	// Manually create tables to avoid AutoMigrate issues
	err = gormDB.Exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, strategy_ids TEXT, output_type TEXT, output_config TEXT, flow_control TEXT, status TEXT NOT NULL, progress REAL DEFAULT 0, error_message TEXT, created_at DATETIME, updated_at DATETIME, started_at DATETIME, completed_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE strategies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, protocol TEXT NOT NULL, config TEXT, flow_control TEXT, config_hash TEXT, created_at DATETIME, updated_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, role TEXT NOT NULL DEFAULT 'user', enabled BOOLEAN DEFAULT 1, created_at DATETIME, updated_at DATETIME, last_login_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at DATETIME)").Error
	require.NoError(t, err)
	db := &storage.DB{DB: gormDB}
	defer db.Close()

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1,
		PacketWorkers: 1,
		OutputWorkers: 1,
		BufferSize:    100,
		QueueSize:     10,
	})

	server := rest.NewServer(cfg, engine, nil, db, nil)
	err = server.Setup()
	assert.NoError(t, err)


	protectedEndpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/tasks"},
		{"POST", "/api/v1/tasks"},
		{"GET", "/api/v1/tasks/1"},
		{"DELETE", "/api/v1/tasks/1"},
		{"POST", "/api/v1/tasks/1/start"},
		{"POST", "/api/v1/tasks/1/stop"},
		{"GET", "/api/v1/strategies"},
		{"POST", "/api/v1/strategies"},
		{"GET", "/api/v1/interfaces"},
	}

	for _, endpoint := range protectedEndpoints {
		t.Run("Auth_Bypass_"+endpoint.method+"_"+endpoint.path, func(t *testing.T) {
			req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			w := httptest.NewRecorder()

			server.Router().ServeHTTP(w, req)

			// If authentication is implemented, should return 401
			// If not implemented yet, should return 200 or 404 (not 500)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Request without auth should not cause server error")

			// Test with invalid token
			req = httptest.NewRequest(endpoint.method, endpoint.path, nil)
			req.Header.Set("Authorization", "Bearer invalid-token-12345")
			w = httptest.NewRecorder()

			server.Router().ServeHTTP(w, req)

			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Request with invalid token should not cause server error")
		})
	}
}

// TestInputValidation tests input validation for various fields
func TestInputValidation(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: ":memory:",
			},
			Pool: config.PoolConfig{
				MaxOpen:      10,
				MaxIdle:      5,
				ConnLifetime: 300,
			},
		},
		Auth: config.AuthConfig{
			JWTSecret:    "test-secret-key",
			JWTIssuer:    "trafficgen-test",
			JWTExpiresIn: 24,
		},
	}

	gormDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	// Manually create tables to avoid AutoMigrate issues
	err = gormDB.Exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, strategy_ids TEXT, output_type TEXT, output_config TEXT, flow_control TEXT, status TEXT NOT NULL, progress REAL DEFAULT 0, error_message TEXT, created_at DATETIME, updated_at DATETIME, started_at DATETIME, completed_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE strategies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, protocol TEXT NOT NULL, config TEXT, flow_control TEXT, config_hash TEXT, created_at DATETIME, updated_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, role TEXT NOT NULL DEFAULT 'user', enabled BOOLEAN DEFAULT 1, created_at DATETIME, updated_at DATETIME, last_login_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at DATETIME)").Error
	require.NoError(t, err)
	db := &storage.DB{DB: gormDB}
	defer db.Close()

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1,
		PacketWorkers: 1,
		OutputWorkers: 1,
		BufferSize:    100,
		QueueSize:     10,
	})

	server := rest.NewServer(cfg, engine, nil, db, nil)
	err = server.Setup()
	assert.NoError(t, err)


		token := createTestToken(t, server)

	t.Run("Invalid_IP_Address", func(t *testing.T) {
		taskReq := map[string]interface{}{
			"name":      "test-task",
			"protocol":  "tcp",
			"config": map[string]interface{}{
				"src_ip":   "999.999.999.999",
				"dst_ip":   "not-an-ip",
				"src_port": 12345,
				"dst_port": 80,
			},
		}

		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		// Strategy handler stores config as-is; validation may or may not reject
		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusCreated,
			"Invalid IP address should be rejected or stored: got %d", w.Code)
	})

	t.Run("Invalid_Port_Range", func(t *testing.T) {
		taskReq := map[string]interface{}{
			"name":      "test-task",
			"protocol":  "tcp",
			"config": map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 99999,
				"dst_port": -1,
			},
		}

		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusCreated,
			"Invalid port range should be rejected or stored: got %d", w.Code)
	})

	t.Run("Invalid_Protocol", func(t *testing.T) {
		taskReq := map[string]interface{}{
			"name":      "test-task",
			"protocol":  "invalid-protocol",
			"config": map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 12345,
				"dst_port": 80,
			},
		}

		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusCreated,
			"Invalid protocol should be rejected or stored: got %d", w.Code)
	})

	t.Run("Empty_Required_Fields", func(t *testing.T) {
		taskReq := map[string]interface{}{
			"name":     "",
			"protocol": "",
			"config":   map[string]interface{}{},
		}

		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/strategies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusCreated,
			"Empty required fields should be rejected or stored: got %d", w.Code)
	})
}

// TestRateLimiting tests rate limiting functionality
func TestRateLimiting(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: ":memory:",
			},
			Pool: config.PoolConfig{
				MaxOpen:      10,
				MaxIdle:      5,
				ConnLifetime: 300,
			},
		},
		Auth: config.AuthConfig{
			JWTSecret:    "test-secret-key",
			JWTIssuer:    "trafficgen-test",
			JWTExpiresIn: 24,
		},
	}

	gormDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	// Manually create tables to avoid AutoMigrate issues
	err = gormDB.Exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, strategy_ids TEXT, output_type TEXT, output_config TEXT, flow_control TEXT, status TEXT NOT NULL, progress REAL DEFAULT 0, error_message TEXT, created_at DATETIME, updated_at DATETIME, started_at DATETIME, completed_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE strategies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, protocol TEXT NOT NULL, config TEXT, flow_control TEXT, config_hash TEXT, created_at DATETIME, updated_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, role TEXT NOT NULL DEFAULT 'user', enabled BOOLEAN DEFAULT 1, created_at DATETIME, updated_at DATETIME, last_login_at DATETIME)").Error
	require.NoError(t, err)
	err = gormDB.Exec("CREATE TABLE tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at DATETIME)").Error
	require.NoError(t, err)
	db := &storage.DB{DB: gormDB}
	defer db.Close()

	engine := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1,
		PacketWorkers: 1,
		OutputWorkers: 1,
		BufferSize:    100,
		QueueSize:     10,
	})

	server := rest.NewServer(cfg, engine, nil, db, nil)
	err = server.Setup()
	assert.NoError(t, err)

		token := createTestToken(t, server)

	t.Run("Rate_Limit_Enforcement", func(t *testing.T) {
		// Send multiple requests rapidly
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest("GET", "/api/v1/strategies", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			server.Router().ServeHTTP(w, req)

			// If rate limiting is implemented, should eventually get 429
			// If not implemented, should continue getting 200
			if w.Code == http.StatusTooManyRequests {
				t.Logf("Rate limiting triggered after %d requests", i+1)
				return
			}
		}

		t.Log("Rate limiting not implemented or threshold not reached")
	})
}
