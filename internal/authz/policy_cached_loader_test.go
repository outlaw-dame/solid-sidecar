// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCachedPolicyLoaderCreation tests creating a cached policy loader
func TestCachedPolicyLoaderCreation(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	cacheStore, _ := NewInMemoryPolicyCacheStore(nil, time.Now().Unix())

	cachedLoader, err := NewCachedPolicyLoader(DefaultCachedPolicyLoaderOptions(loader, cacheStore))
	if err != nil {
		t.Fatalf("failed to create cached policy loader: %v", err)
	}
	if cachedLoader == nil {
		t.Fatal("cached loader is nil")
	}
}

// TestCachedPolicyLoaderNilLoader tests error handling for nil loader
func TestCachedPolicyLoaderNilLoader(t *testing.T) {
	cacheStore, _ := NewInMemoryPolicyCacheStore(nil, time.Now().Unix())

	_, err := NewCachedPolicyLoader(CachedPolicyLoaderOptions{
		Loader:     nil,
		CacheStore: cacheStore,
	})
	if err == nil {
		t.Fatal("expected error for nil loader, got nil")
	}
}

// TestCachedPolicyLoaderNilCacheStore tests error handling for nil cache store
func TestCachedPolicyLoaderNilCacheStore(t *testing.T) {
	loader := NewPolicyHTTPLoader()

	_, err := NewCachedPolicyLoader(CachedPolicyLoaderOptions{
		Loader:     loader,
		CacheStore: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil cache store, got nil")
	}
}

// TestCachedPolicyLoaderCacheMiss tests cache miss behavior
func TestCachedPolicyLoaderCacheMiss(t *testing.T) {
	// Create a test server that returns a policy
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	cacheStore, _ := NewInMemoryPolicyCacheStore(nil, time.Now().Unix())
	cachedLoader, _ := NewCachedPolicyLoader(DefaultCachedPolicyLoaderOptions(loader, cacheStore))

	source := PolicySource{URI: server.URL, Kind: PolicySourceExplicit, ContentType: "text/turtle"}

	// First load should be a cache miss
	result, err := cachedLoader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("first load failed: %v", err)
	}
	if len(result.Loaded.Content) == 0 {
		t.Fatal("expected content, got empty")
	}
	if string(result.Loaded.Content) != policyContent {
		t.Errorf("expected content %q, got %q", policyContent, string(result.Loaded.Content))
	}
}

// TestCachedPolicyLoaderCacheHit tests cache hit behavior
func TestCachedPolicyLoaderCacheHit(t *testing.T) {
	// Create a test server that returns a policy
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	cacheStore, _ := NewInMemoryPolicyCacheStore(nil, time.Now().Unix())
	cachedLoader, _ := NewCachedPolicyLoader(DefaultCachedPolicyLoaderOptions(loader, cacheStore))

	source := PolicySource{URI: server.URL, Kind: PolicySourceExplicit, ContentType: "text/turtle"}

	// First load - cache miss
	result1, err := cachedLoader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("first load failed: %v", err)
	}

	// Second load - should be cache hit
	result2, err := cachedLoader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("second load failed: %v", err)
	}

	// Both results should have the same content
	if string(result1.Loaded.Content) != string(result2.Loaded.Content) {
		t.Errorf("cache hit content mismatch: %q vs %q",
			string(result1.Loaded.Content), string(result2.Loaded.Content))
	}

	// Cache metadata should be set
	if result2.Metadata.CacheKey == "" {
		t.Error("expected cache key to be set")
	}
	if result2.Metadata.State != PolicyCacheFresh {
		t.Errorf("expected fresh state, got %q", result2.Metadata.State)
	}
}

// TestCachedPolicyLoaderCacheExpiry tests cache expiry behavior
func TestCachedPolicyLoaderCacheExpiry(t *testing.T) {
	// Create a test server that returns a policy
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	// Create cache store with past expiry time
	pastUnix := time.Now().Add(-10 * time.Minute).Unix()
	cacheStore, _ := NewInMemoryPolicyCacheStore(nil, pastUnix)

	// Use very short expiry duration
	cachedLoader, _ := NewCachedPolicyLoader(CachedPolicyLoaderOptions{
		Loader:                loader,
		CacheStore:            cacheStore,
		DefaultExpiryDuration: 1 * time.Nanosecond, // Very short expiry
		Metrics:               NewPolicyCacheMetrics(),
	})

	source := PolicySource{URI: server.URL, Kind: PolicySourceExplicit, ContentType: "text/turtle"}

	// First load
	_, err := cachedLoader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("first load failed: %v", err)
	}

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	// Second load should refresh because first entry expired
	result, err := cachedLoader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("second load failed: %v", err)
	}

	// Should have fresh content
	if string(result.Loaded.Content) != policyContent {
		t.Errorf("expected content %q, got %q", policyContent, string(result.Loaded.Content))
	}
}

// TestCachedPolicyLoaderWithMetrics tests metrics recording
func TestCachedPolicyLoaderWithMetrics(t *testing.T) {
	// Create a test server that returns a policy
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	cacheStore, _ := NewInMemoryPolicyCacheStore(nil, time.Now().Unix())
	metrics := NewPolicyCacheMetrics()

	cachedLoader, _ := NewCachedPolicyLoader(CachedPolicyLoaderOptions{
		Loader:                loader,
		CacheStore:            cacheStore,
		DefaultExpiryDuration: 5 * time.Minute,
		Metrics:               metrics,
	})

	source := PolicySource{URI: server.URL, Kind: PolicySourceExplicit, ContentType: "text/turtle"}

	// First load - cache miss
	_, err := cachedLoader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("first load failed: %v", err)
	}

	// Second load - cache hit
	_, err = cachedLoader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("second load failed: %v", err)
	}

	// Check metrics
	stats := metrics.CacheStats()
	if stats["misses"] != 1 {
		t.Errorf("expected 1 miss, got %d", stats["misses"])
	}
	if stats["hits"] != 1 {
		t.Errorf("expected 1 hit, got %d", stats["hits"])
	}
	if stats["load_successes"] != 1 {
		t.Errorf("expected 1 load success, got %d", stats["load_successes"])
	}
}

// TestCachedPolicyLoaderCacheErrorFallback tests fallback behavior on cache errors
func TestCachedPolicyLoaderCacheErrorFallback(t *testing.T) {
	// Create a test server that returns a policy
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	// Create a failing cache store to simulate cache errors
	failingCache := &mockFailingCacheStore{}
	cachedLoader, _ := NewCachedPolicyLoader(CachedPolicyLoaderOptions{
		Loader:                loader,
		CacheStore:            failingCache, // This will cause cache errors
		DefaultExpiryDuration: 5 * time.Minute,
		Metrics:               NewPolicyCacheMetrics(),
	})

	source := PolicySource{URI: server.URL, Kind: PolicySourceExplicit, ContentType: "text/turtle"}

	// Should fall back to direct load on cache error
	result, err := cachedLoader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	// Should still get the content
	if string(result.Loaded.Content) != policyContent {
		t.Errorf("expected content %q, got %q", policyContent, string(result.Loaded.Content))
	}
}

// TestCachedPolicyLoaderWithCacheSize tests cache size functionality
func TestCachedPolicyLoaderWithCacheSize(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	cacheStore, _ := NewInMemoryPolicyCacheStore(nil, time.Now().Unix())
	cachedLoader, _ := NewCachedPolicyLoader(DefaultCachedPolicyLoaderOptions(loader, cacheStore))

	// Check initial cache size
	size, err := cachedLoader.CacheSize(context.Background())
	if err != nil {
		t.Fatalf("failed to get cache size: %v", err)
	}
	if size != 0 {
		t.Errorf("expected initial cache size 0, got %d", size)
	}
}

// mockFailingCacheStore is a mock cache store that always fails
type mockFailingCacheStore struct{}

func (m *mockFailingCacheStore) GetPolicyCacheRecord(ctx context.Context, source PolicySource) (PolicySourceCacheRecord, bool, error) {
	return PolicySourceCacheRecord{}, false, errors.New("cache error")
}

func (m *mockFailingCacheStore) PutPolicyCacheRecord(ctx context.Context, record PolicySourceCacheRecord) error {
	return errors.New("cache error")
}

func (m *mockFailingCacheStore) ListPolicyCacheRecords(ctx context.Context) ([]PolicySourceCacheRecord, error) {
	return nil, errors.New("cache error")
}

// TestCachedPolicyLoaderFailingCacheStore tests behavior with a failing cache store
func TestCachedPolicyLoaderFailingCacheStore(t *testing.T) {
	// Create a test server that returns a policy
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	failingCache := &mockFailingCacheStore{}
	cachedLoader, _ := NewCachedPolicyLoader(CachedPolicyLoaderOptions{
		Loader:                loader,
		CacheStore:            failingCache,
		DefaultExpiryDuration: 5 * time.Minute,
		Metrics:               NewPolicyCacheMetrics(),
	})

	source := PolicySource{URI: server.URL, Kind: PolicySourceExplicit, ContentType: "text/turtle"}

	// Should fall back to direct load on cache errors
	result, err := cachedLoader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	// Should still get the content
	if string(result.Loaded.Content) != policyContent {
		t.Errorf("expected content %q, got %q", policyContent, string(result.Loaded.Content))
	}
}

// TestDefaultCachedPolicyLoaderOptions tests the default options
func TestDefaultCachedPolicyLoaderOptions(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	cacheStore, _ := NewInMemoryPolicyCacheStore(nil, time.Now().Unix())

	options := DefaultCachedPolicyLoaderOptions(loader, cacheStore)

	if options.Loader == nil {
		t.Error("expected loader to be set")
	}
	if options.CacheStore == nil {
		t.Error("expected cache store to be set")
	}
	if options.DefaultExpiryDuration != 5*time.Minute {
		t.Errorf("expected default expiry 5m, got %v", options.DefaultExpiryDuration)
	}
	if options.MaxCacheSize != 100 {
		t.Errorf("expected max cache size 100, got %d", options.MaxCacheSize)
	}
	if options.Metrics == nil {
		t.Error("expected metrics to be set")
	}
}

// TestCachedPolicyLoaderDifferentSources tests loading different policy sources
func TestCachedPolicyLoaderDifferentSources(t *testing.T) {
	// Create two test servers
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<https://example1.org/resource> a solid:Resource .`)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<https://example2.org/resource> a solid:Resource .`)
	}))
	defer server2.Close()

	loader := NewPolicyHTTPLoader()
	cacheStore, _ := NewInMemoryPolicyCacheStore(nil, time.Now().Unix())
	cachedLoader, _ := NewCachedPolicyLoader(DefaultCachedPolicyLoaderOptions(loader, cacheStore))

	source1 := PolicySource{URI: server1.URL, Kind: PolicySourceExplicit, ContentType: "text/turtle"}
	source2 := PolicySource{URI: server2.URL, Kind: PolicySourceExplicit, ContentType: "text/turtle"}

	// Load both sources
	result1, err := cachedLoader.LoadPolicySource(context.Background(), source1)
	if err != nil {
		t.Fatalf("load 1 failed: %v", err)
	}

	result2, err := cachedLoader.LoadPolicySource(context.Background(), source2)
	if err != nil {
		t.Fatalf("load 2 failed: %v", err)
	}

	// Should have different content
	if string(result1.Loaded.Content) == string(result2.Loaded.Content) {
		t.Error("expected different content for different sources")
	}

	// Should have different cache keys
	if result1.Metadata.CacheKey == result2.Metadata.CacheKey {
		t.Error("expected different cache keys for different sources")
	}
}

// TestNopPolicyCacheMetricsRecorder tests the no-op metrics recorder
func TestNopPolicyCacheMetricsRecorder(t *testing.T) {
	recorder := NewNopPolicyCacheMetricsRecorder()

	// Should not panic
	recorder.RecordCacheHit()
	recorder.RecordCacheMiss()
	recorder.RecordCacheExpiry()
	recorder.RecordCacheError()
	recorder.RecordCacheStoreError()
	recorder.RecordLoadSuccess()
	recorder.RecordLoadError()
}

// TestPolicyCacheMetrics tests the concrete metrics implementation
func TestPolicyCacheMetrics(t *testing.T) {
	metrics := NewPolicyCacheMetrics()

	// Record various events
	metrics.RecordCacheHit()
	metrics.RecordCacheHit()
	metrics.RecordCacheMiss()
	metrics.RecordCacheExpiry()
	metrics.RecordCacheError()
	metrics.RecordLoadSuccess()
	metrics.RecordLoadSuccess()
	metrics.RecordLoadError()

	// Check stats
	stats := metrics.CacheStats()
	if stats["hits"] != 2 {
		t.Errorf("expected 2 hits, got %d", stats["hits"])
	}
	if stats["misses"] != 1 {
		t.Errorf("expected 1 miss, got %d", stats["misses"])
	}
	if stats["expiries"] != 1 {
		t.Errorf("expected 1 expiry, got %d", stats["expiries"])
	}
	if stats["errors"] != 1 {
		t.Errorf("expected 1 error, got %d", stats["errors"])
	}
	if stats["load_successes"] != 2 {
		t.Errorf("expected 2 load successes, got %d", stats["load_successes"])
	}
	if stats["load_errors"] != 1 {
		t.Errorf("expected 1 load error, got %d", stats["load_errors"])
	}
}
