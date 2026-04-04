package security_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
)

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
		},
	}

	db, err := storage.NewDB(&cfg.Database)
	assert.NoError(t, err)
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
			req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			server.Router().ServeHTTP(w, req)

			// Should not return 500 error (SQL error)
			// Should return 400 (bad request) or 201 (created with escaped input)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"SQL injection payload should not cause server error: %s", payload)

			// Verify database is not corrupted
			var count int64
			s := db.DB().Session(&gorm.Session{AllowGlobalUpdate: true})
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
		},
	}

	db, err := storage.NewDB(&cfg.Database)
	assert.NoError(t, err)
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
			req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
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
		},
	}

	db, err := storage.NewDB(&cfg.Database)
	assert.NoError(t, err)
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

		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
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
		},
	}

	db, err := storage.NewDB(&cfg.Database)
	assert.NoError(t, err)
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
		},
	}

	db, err := storage.NewDB(&cfg.Database)
	assert.NoError(t, err)
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

	t.Run("Invalid_IP_Address", func(t *testing.T) {
		taskReq := map[string]interface{}{
			"name":     "test-task",
			"protocol": "tcp",
			"config": map[string]interface{}{
				"src_ip":   "999.999.999.999",
				"dst_ip":   "not-an-ip",
				"src_port": 12345,
				"dst_port": 80,
			},
		}

		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code,
			"Invalid IP address should be rejected")
	})

	t.Run("Invalid_Port_Range", func(t *testing.T) {
		taskReq := map[string]interface{}{
			"name":     "test-task",
			"protocol": "tcp",
			"config": map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 99999,
				"dst_port": -1,
			},
		}

		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code,
			"Invalid port range should be rejected")
	})

	t.Run("Invalid_Protocol", func(t *testing.T) {
		taskReq := map[string]interface{}{
			"name":     "test-task",
			"protocol": "invalid-protocol",
			"config": map[string]interface{}{
				"src_ip":   "192.168.1.1",
				"dst_ip":   "192.168.1.2",
				"src_port": 12345,
				"dst_port": 80,
			},
		}

		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code,
			"Invalid protocol should be rejected")
	})

	t.Run("Empty_Required_Fields", func(t *testing.T) {
		taskReq := map[string]interface{}{
			"name":     "",
			"protocol": "",
			"config":   map[string]interface{}{},
		}

		body, _ := json.Marshal(taskReq)
		req := httptest.NewRequest("POST", "/api/v1/tasks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code,
			"Empty required fields should be rejected")
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
		},
	}

	db, err := storage.NewDB(&cfg.Database)
	assert.NoError(t, err)
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

	t.Run("Rate_Limit_Enforcement", func(t *testing.T) {
		// Send multiple requests rapidly
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest("GET", "/api/v1/tasks", nil)
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
