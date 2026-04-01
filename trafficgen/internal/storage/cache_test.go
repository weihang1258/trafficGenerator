package storage

import (
	"testing"
)

func TestCache_LocalCache(t *testing.T) {
	// Create cache with invalid Redis address (will use local cache)
	cache, err := New(Config{
		Addr:     "localhost:9999", // Invalid address
		TTL:      5 * 60 * 1000000000, // 5 minutes in nanoseconds
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer cache.Close()

	// Should be degraded to local cache
	if !cache.IsDegraded() {
		t.Error("Cache should be degraded to local cache")
	}

	// Test Set and Get
	err = cache.Set(nil, "key1", "value1", 0)
	if err != nil {
		t.Errorf("Set() error = %v", err)
	}

	val, err := cache.Get(nil, "key1")
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if val != "value1" {
		t.Errorf("Get() = %s, want value1", val)
	}

	// Test Exists
	exists, err := cache.Exists(nil, "key1")
	if err != nil {
		t.Errorf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Exists() should return true")
	}

	// Test Delete
	err = cache.Delete(nil, "key1")
	if err != nil {
		t.Errorf("Delete() error = %v", err)
	}

	// Should not exist after delete
	exists, _ = cache.Exists(nil, "key1")
	if exists {
		t.Error("Exists() should return false after delete")
	}
}

func TestCache_SetNX(t *testing.T) {
	cache, _ := New(Config{
		Addr: "localhost:9999",
	})
	defer cache.Close()

	// First SetNX should succeed
	ok, err := cache.SetNX(nil, "key1", "value1", 0)
	if err != nil {
		t.Errorf("SetNX() error = %v", err)
	}
	if !ok {
		t.Error("First SetNX should succeed")
	}

	// Second SetNX should fail (key exists)
	ok, _ = cache.SetNX(nil, "key1", "value2", 0)
	if ok {
		t.Error("Second SetNX should fail")
	}
}

func TestCache_GetOrSet(t *testing.T) {
	cache, _ := New(Config{
		Addr: "localhost:9999",
	})
	defer cache.Close()

	called := false
	fn := func() (string, error) {
		called = true
		return "generated", nil
	}

	// First call should generate
	val, err := cache.GetOrSet(nil, "key1", fn, 0)
	if err != nil {
		t.Fatalf("GetOrSet() error = %v", err)
	}
	if val != "generated" {
		t.Errorf("GetOrSet() = %s, want generated", val)
	}
	if !called {
		t.Error("Generator function should be called")
	}

	// Second call should use cache
	called = false
	val, _ = cache.GetOrSet(nil, "key1", fn, 0)
	if called {
		t.Error("Generator function should not be called for cached value")
	}
}

func TestCache_Stats(t *testing.T) {
	cache, _ := New(Config{
		Addr: "localhost:9999",
	})
	defer cache.Close()

	// Add some items
	cache.Set(nil, "key1", "value1", 0)
	cache.Set(nil, "key2", "value2", 0)

	stats := cache.Stats()
	if !stats["degraded"].(bool) {
		t.Error("Stats should show degraded = true")
	}
	if stats["local_cache_size"].(int) != 2 {
		t.Errorf("local_cache_size = %v, want 2", stats["local_cache_size"])
	}
}
