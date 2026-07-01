package cache

import (
	"context"
	"testing"
	"time"
)

// =============================================================================
// Configuration Tests
// =============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.TTL != 5*time.Minute {
		t.Errorf("Expected default TTL to be 5 minutes, got %v", cfg.TTL)
	}
	if cfg.MaxTTL != 1*time.Hour {
		t.Errorf("Expected default MaxTTL to be 1 hour, got %v", cfg.MaxTTL)
	}
	if cfg.StaleTTL != 30*time.Second {
		t.Errorf("Expected default StaleTTL to be 30 seconds, got %v", cfg.StaleTTL)
	}
	if cfg.MaxSize != 10000 {
		t.Errorf("Expected default MaxSize to be 10000, got %d", cfg.MaxSize)
	}
	if cfg.EnableNegativeCache != false {
		t.Error("Expected default EnableNegativeCache to be false")
	}
	if cfg.NegativeCacheTTL != 1*time.Minute {
		t.Errorf("Expected default NegativeCacheTTL to be 1 minute, got %v", cfg.NegativeCacheTTL)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				TTL:                 5 * time.Minute,
				MaxTTL:              1 * time.Hour,
				StaleTTL:            30 * time.Second,
				MaxSize:             1000,
				EnableNegativeCache: true,
				NegativeCacheTTL:    1 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "zero TTL",
			cfg: Config{
				TTL:      0,
				MaxTTL:   1 * time.Hour,
				StaleTTL: 30 * time.Second,
				MaxSize:  1000,
			},
			wantErr: true,
		},
		{
			name: "zero MaxTTL",
			cfg: Config{
				TTL:      5 * time.Minute,
				MaxTTL:   0,
				StaleTTL: 30 * time.Second,
				MaxSize:  1000,
			},
			wantErr: true,
		},
		{
			name: "stale TTL exceeds TTL",
			cfg: Config{
				TTL:      5 * time.Minute,
				MaxTTL:   1 * time.Hour,
				StaleTTL: 10 * time.Minute, // > TTL
				MaxSize:  1000,
			},
			wantErr: true,
		},
		{
			name: "zero MaxSize",
			cfg: Config{
				TTL:      5 * time.Minute,
				MaxTTL:   1 * time.Hour,
				StaleTTL: 30 * time.Second,
				MaxSize:  0,
			},
			wantErr: true,
		},
		{
			name: "negative cache enabled but zero TTL",
			cfg: Config{
				TTL:                 5 * time.Minute,
				MaxTTL:              1 * time.Hour,
				StaleTTL:            30 * time.Second,
				MaxSize:             1000,
				EnableNegativeCache: true,
				NegativeCacheTTL:    0,
			},
			wantErr: true,
		},
		{
			name: "negative cache TTL exceeds TTL",
			cfg: Config{
				TTL:                 5 * time.Minute,
				MaxTTL:              1 * time.Hour,
				StaleTTL:            30 * time.Second,
				MaxSize:             1000,
				EnableNegativeCache: true,
				NegativeCacheTTL:    10 * time.Minute, // > TTL
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// CacheKey Tests
// =============================================================================

func TestCacheKeyString(t *testing.T) {
	tests := []struct {
		name     string
		key1     *CacheKey
		key2     *CacheKey
		wantSame bool
	}{
		{
			name: "same keys produce same string",
			key1: &CacheKey{
				Agent:            "https://example.com/webid#me",
				DID:              "did:solid:example",
				Client:           "client1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			key2: &CacheKey{
				Agent:            "https://example.com/webid#me",
				DID:              "did:solid:example",
				Client:           "client1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			wantSame: true,
		},
		{
			name: "different agent produces different string",
			key1: &CacheKey{
				Agent:            "https://example.com/webid#me",
				DID:              "did:solid:example",
				Client:           "client1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			key2: &CacheKey{
				Agent:            "https://example.com/webid#you",
				DID:              "did:solid:example",
				Client:           "client1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			wantSame: false,
		},
		{
			name: "different resource produces different string",
			key1: &CacheKey{
				Agent:            "https://example.com/webid#me",
				DID:              "did:solid:example",
				Client:           "client1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			key2: &CacheKey{
				Agent:            "https://example.com/webid#me",
				DID:              "did:solid:example",
				Client:           "client1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource2",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			wantSame: false,
		},
		{
			name: "different method produces different string",
			key1: &CacheKey{
				Agent:            "https://example.com/webid#me",
				DID:              "did:solid:example",
				Client:           "client1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			key2: &CacheKey{
				Agent:            "https://example.com/webid#me",
				DID:              "did:solid:example",
				Client:           "client1",
				Method:           "POST",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			wantSame: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str1 := tt.key1.String()
			str2 := tt.key2.String()
			if (str1 == str2) != tt.wantSame {
				t.Errorf("CacheKey.String() same = %v, want %v", str1 == str2, tt.wantSame)
			}
			// Also check that strings are not empty
			if str1 == "" || str2 == "" {
				t.Error("CacheKey.String() returned empty string")
			}
			// Check that strings are of reasonable length (64 chars for SHA-256)
			if len(str1) != 64 || len(str2) != 64 {
				t.Errorf("CacheKey.String() length = %d, %d, want 64", len(str1), len(str2))
			}
		})
	}
}

// =============================================================================
// MemoryCache Tests
// =============================================================================

func TestMemoryCache_BasicOperations(t *testing.T) {
	cfg := DefaultConfig()
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Test Put and Get
	key := &CacheKey{
		Agent:            "https://example.com/webid#me",
		Method:           "GET",
		Mode:             "read",
		Resource:         "https://example.com/resource",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		EvaluatorVersion: "v1",
	}

	decision := &Decision{
		Allow:            true,
		Reason:           "Allowed by policy",
		EvaluatorVersion: "v1",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		CreatedAt:        time.Now(),
	}

	// Put decision
	err = cache.Put(ctx, key, decision)
	if err != nil {
		t.Fatalf("Failed to put decision: %v", err)
	}

	// Get decision
	gotDecision, got := cache.Get(ctx, key)
	if !got {
		t.Fatal("Expected to get decision, got none")
	}
	if gotDecision.Allow != true {
		t.Errorf("Expected Allow=true, got %v", gotDecision.Allow)
	}
	if gotDecision.Reason != "Allowed by policy" {
		t.Errorf("Expected reason 'Allowed by policy', got %q", gotDecision.Reason)
	}

	// Test Get with non-existent key
	nonExistentKey := &CacheKey{
		Agent:            "https://example.com/webid#nonexistent",
		Method:           "GET",
		Mode:             "read",
		Resource:         "https://example.com/other",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		EvaluatorVersion: "v1",
	}
	_, got = cache.Get(ctx, nonExistentKey)
	if got {
		t.Error("Expected no decision for non-existent key")
	}
}

func TestMemoryCache_Expiration(t *testing.T) {
	cfg := Config{
		TTL:                 50 * time.Millisecond,
		MaxTTL:              100 * time.Millisecond,
		StaleTTL:            25 * time.Millisecond,
		MaxSize:             1000,
		EnableNegativeCache: false,
		NegativeCacheTTL:    50 * time.Millisecond,
	}
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	key := &CacheKey{
		Agent:            "https://example.com/webid#me",
		Method:           "GET",
		Mode:             "read",
		Resource:         "https://example.com/resource",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		EvaluatorVersion: "v1",
	}

	decision := &Decision{
		Allow:            true,
		Reason:           "Allowed",
		EvaluatorVersion: "v1",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		CreatedAt:        time.Now(),
	}

	// Put decision
	err = cache.Put(ctx, key, decision)
	if err != nil {
		t.Fatalf("Failed to put decision: %v", err)
	}

	// Get decision (should exist)
	_, got := cache.Get(ctx, key)
	if !got {
		t.Fatal("Expected to get decision immediately after put")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Get decision (should not exist)
	_, got = cache.Get(ctx, key)
	if got {
		t.Error("Expected decision to have expired")
	}
}

func TestMemoryCache_NegativeCache(t *testing.T) {
	cfg := Config{
		TTL:                 5 * time.Minute,
		MaxTTL:              1 * time.Hour,
		StaleTTL:            30 * time.Second,
		MaxSize:             1000,
		EnableNegativeCache: true,
		NegativeCacheTTL:    1 * time.Minute,
	}
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	key := &CacheKey{
		Agent:            "https://example.com/webid#me",
		Method:           "GET",
		Mode:             "read",
		Resource:         "https://example.com/resource",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		EvaluatorVersion: "v1",
	}

	// Test with negative decision (deny)
	denyDecision := &Decision{
		Allow:            false,
		Reason:           "Denied by policy",
		EvaluatorVersion: "v1",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		CreatedAt:        time.Now(),
	}

	// Put negative decision
	err = cache.Put(ctx, key, denyDecision)
	if err != nil {
		t.Fatalf("Failed to put negative decision: %v", err)
	}

	// Get decision (should exist)
	gotDecision, got := cache.Get(ctx, key)
	if !got {
		t.Fatal("Expected to get negative decision")
	}
	if gotDecision.Allow != false {
		t.Errorf("Expected Allow=false, got %v", gotDecision.Allow)
	}
}

func TestMemoryCache_NegativeCacheDisabled(t *testing.T) {
	cfg := Config{
		TTL:                 5 * time.Minute,
		MaxTTL:              1 * time.Hour,
		StaleTTL:            30 * time.Second,
		MaxSize:             1000,
		EnableNegativeCache: false, // Disabled
		NegativeCacheTTL:    1 * time.Minute,
	}
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	key := &CacheKey{
		Agent:            "https://example.com/webid#me",
		Method:           "GET",
		Mode:             "read",
		Resource:         "https://example.com/resource",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		EvaluatorVersion: "v1",
	}

	// Test with negative decision (deny)
	denyDecision := &Decision{
		Allow:            false,
		Reason:           "Denied by policy",
		EvaluatorVersion: "v1",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		CreatedAt:        time.Now(),
	}

	// Put negative decision (should not be cached)
	err = cache.Put(ctx, key, denyDecision)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Get decision (should not exist because negative cache is disabled)
	_, got := cache.Get(ctx, key)
	if got {
		t.Error("Expected negative decision to not be cached when negative cache is disabled")
	}
}

func TestMemoryCache_Invalidation(t *testing.T) {
	cfg := DefaultConfig()
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Create multiple entries with same policy version
	entries := []struct {
		key      *CacheKey
		decision *Decision
	}{
		{
			key: &CacheKey{
				Agent:            "https://example.com/webid#1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
		},
		{
			key: &CacheKey{
				Agent:            "https://example.com/webid#2",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource2",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
		},
		{
			key: &CacheKey{
				Agent:            "https://example.com/webid#1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource3",
				PolicyVersion:    "v2", // Different policy version
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v2",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
		},
	}

	// Put all entries
	for _, entry := range entries {
		err := cache.Put(ctx, entry.key, entry.decision)
		if err != nil {
			t.Fatalf("Failed to put entry: %v", err)
		}
	}

	// Verify all entries exist
	for _, entry := range entries {
		_, got := cache.Get(ctx, entry.key)
		if !got {
			t.Errorf("Expected to get entry for key %v", entry.key.String())
		}
	}

	// Invalidate by policy version "v1"
	err = cache.InvalidatePolicy(ctx, "v1")
	if err != nil {
		t.Fatalf("Failed to invalidate by policy: %v", err)
	}

	// Check that v1 entries are gone but v2 entry remains
	if _, got := cache.Get(ctx, entries[0].key); got {
		t.Error("Expected v1 policy entry to be invalidated")
	}
	if _, got := cache.Get(ctx, entries[1].key); got {
		t.Error("Expected v1 policy entry to be invalidated")
	}
	if _, got := cache.Get(ctx, entries[2].key); !got {
		t.Error("Expected v2 policy entry to still exist")
	}
}

func TestMemoryCache_InvalidateResource(t *testing.T) {
	cfg := DefaultConfig()
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Create entries for same resource
	entries := []struct {
		key      *CacheKey
		decision *Decision
	}{
		{
			key: &CacheKey{
				Agent:            "https://example.com/webid#1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
		},
		{
			key: &CacheKey{
				Agent:            "https://example.com/webid#2",
				Method:           "POST",
				Mode:             "write",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
		},
	}

	// Put all entries
	for _, entry := range entries {
		err := cache.Put(ctx, entry.key, entry.decision)
		if err != nil {
			t.Fatalf("Failed to put entry: %v", err)
		}
	}

	// Invalidate by resource
	err = cache.InvalidateResource(ctx, "https://example.com/resource")
	if err != nil {
		t.Fatalf("Failed to invalidate by resource: %v", err)
	}

	// Check that all entries for the resource are gone
	for _, entry := range entries {
		if _, got := cache.Get(ctx, entry.key); got {
			t.Error("Expected resource entry to be invalidated")
		}
	}
}

func TestMemoryCache_InvalidateAgent(t *testing.T) {
	cfg := DefaultConfig()
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Create entries for same agent
	entries := []struct {
		key      *CacheKey
		decision *Decision
	}{
		{
			key: &CacheKey{
				Agent:            "https://example.com/webid#1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
		},
		{
			key: &CacheKey{
				Agent:            "https://example.com/webid#1",
				Method:           "POST",
				Mode:             "write",
				Resource:         "https://example.com/resource2",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
		},
	}

	// Put all entries
	for _, entry := range entries {
		err := cache.Put(ctx, entry.key, entry.decision)
		if err != nil {
			t.Fatalf("Failed to put entry: %v", err)
		}
	}

	// Invalidate by agent
	err = cache.InvalidateAgent(ctx, "https://example.com/webid#1")
	if err != nil {
		t.Fatalf("Failed to invalidate by agent: %v", err)
	}

	// Check that all entries for the agent are gone
	for _, entry := range entries {
		if _, got := cache.Get(ctx, entry.key); got {
			t.Error("Expected agent entry to be invalidated")
		}
	}
}

func TestMemoryCache_Clear(t *testing.T) {
	cfg := DefaultConfig()
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Create some entries
	for i := 0; i < 10; i++ {
		key := &CacheKey{
			Agent:            "https://example.com/webid#" + string(rune('a'+i)),
			Method:           "GET",
			Mode:             "read",
			Resource:         "https://example.com/resource" + string(rune('a'+i)),
			PolicyVersion:    "v1",
			ParserVersion:    "v1",
			EvaluatorVersion: "v1",
		}
		decision := &Decision{
			Allow:            true,
			Reason:           "Allowed",
			EvaluatorVersion: "v1",
			PolicyVersion:    "v1",
			ParserVersion:    "v1",
			CreatedAt:        time.Now(),
		}
		err := cache.Put(ctx, key, decision)
		if err != nil {
			t.Fatalf("Failed to put entry: %v", err)
		}
	}

	// Verify entries exist
	key := &CacheKey{
		Agent:            "https://example.com/webid#a",
		Method:           "GET",
		Mode:             "read",
		Resource:         "https://example.com/resourcea",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		EvaluatorVersion: "v1",
	}
	_, got := cache.Get(ctx, key)
	if !got {
		t.Fatal("Expected entry to exist before clear")
	}

	// Clear cache
	err = cache.Clear(ctx)
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	// Verify cache is empty
	_, got = cache.Get(ctx, key)
	if got {
		t.Error("Expected cache to be empty after clear")
	}
}

func TestMemoryCache_Eviction(t *testing.T) {
	cfg := Config{
		TTL:                 5 * time.Minute,
		MaxTTL:              1 * time.Hour,
		StaleTTL:            30 * time.Second,
		MaxSize:             5, // Small cache
		EnableNegativeCache: false,
		NegativeCacheTTL:    1 * time.Minute,
	}
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	// Fill the cache
	for i := 0; i < 5; i++ {
		key := &CacheKey{
			Agent:            "https://example.com/webid#" + string(rune('a'+i)),
			Method:           "GET",
			Mode:             "read",
			Resource:         "https://example.com/resource" + string(rune('a'+i)),
			PolicyVersion:    "v1",
			ParserVersion:    "v1",
			EvaluatorVersion: "v1",
		}
		decision := &Decision{
			Allow:            true,
			Reason:           "Allowed",
			EvaluatorVersion: "v1",
			PolicyVersion:    "v1",
			ParserVersion:    "v1",
			CreatedAt:        time.Now(),
		}
		err := cache.Put(ctx, key, decision)
		if err != nil {
			t.Fatalf("Failed to put entry: %v", err)
		}
	}

	// Add one more entry (should trigger eviction)
	key := &CacheKey{
		Agent:            "https://example.com/webid#f",
		Method:           "GET",
		Mode:             "read",
		Resource:         "https://example.com/resourcef",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		EvaluatorVersion: "v1",
	}
	decision := &Decision{
		Allow:            true,
		Reason:           "Allowed",
		EvaluatorVersion: "v1",
		PolicyVersion:    "v1",
		ParserVersion:    "v1",
		CreatedAt:        time.Now(),
	}
	err = cache.Put(ctx, key, decision)
	if err != nil {
		t.Fatalf("Failed to put entry (with eviction): %v", err)
	}

	// Check metrics for eviction
	metrics := cache.Metrics()
	if metrics.Evictions == 0 {
		t.Error("Expected evictions to occur")
	}

	// Check that cache size is at max
	if metrics.CurrentSize > cfg.MaxSize {
		t.Errorf("Expected cache size <= %d, got %d", cfg.MaxSize, metrics.CurrentSize)
	}
}

// =============================================================================
// Cache Poisoning Protection Tests
// =============================================================================

func TestMemoryCache_CachePoisoningProtection(t *testing.T) {
	cfg := DefaultConfig()
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name     string
		key      *CacheKey
		decision *Decision
		wantErr  bool
	}{
		{
			name: "empty agent, DID, and client",
			key: &CacheKey{
				Agent:            "",
				DID:              "",
				Client:           "",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
			wantErr: true,
		},
		{
			name: "empty resource",
			key: &CacheKey{
				Agent:            "https://example.com/webid#me",
				DID:              "",
				Client:           "client1",
				Method:           "GET",
				Mode:             "read",
				Resource:         "",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
			wantErr: true,
		},
		{
			name: "empty method",
			key: &CacheKey{
				Agent:            "https://example.com/webid#me",
				DID:              "",
				Client:           "client1",
				Method:           "",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
			},
			wantErr: true,
		},
		{
			name: "very long TTL",
			key: &CacheKey{
				Agent:            "https://example.com/webid#me",
				Method:           "GET",
				Mode:             "read",
				Resource:         "https://example.com/resource",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				EvaluatorVersion: "v1",
			},
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
				CreatedAt:        time.Now(),
				ExpiresAt:        time.Now().Add(48 * time.Hour), // > 24 hours
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.Put(ctx, tt.key, tt.decision)
			if (err != nil) != tt.wantErr {
				t.Errorf("Put() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Stale Decision Checker Tests
// =============================================================================

func TestStaleDecisionChecker_IsStale(t *testing.T) {
	cfg := DefaultConfig()
	checker := NewStaleDecisionChecker(cfg)

	tests := []struct {
		name     string
		decision *Decision
		want     bool
	}{
		{
			name:     "nil decision is stale",
			decision: nil,
			want:     true,
		},
		{
			name: "expired decision is stale",
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				CreatedAt:        time.Now().Add(-10 * time.Minute),
				ExpiresAt:        time.Now().Add(-5 * time.Minute),
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
			},
			want: true,
		},
		{
			name: "active decision is not stale",
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				CreatedAt:        time.Now(),
				ExpiresAt:        time.Now().Add(10 * time.Minute),
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
			},
			want: false,
		},
		{
			name: "decision within stale TTL is not stale",
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				CreatedAt:        time.Now().Add(-10 * time.Second),
				ExpiresAt:        time.Now().Add(5 * time.Minute),
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checker.IsStale(tt.decision)
			if got != tt.want {
				t.Errorf("IsStale() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStaleDecisionChecker_CanUseStale(t *testing.T) {
	cfg := DefaultConfig()
	checker := NewStaleDecisionChecker(cfg)

	tests := []struct {
		name     string
		decision *Decision
		want     bool
	}{
		{
			name:     "nil decision cannot be used",
			decision: nil,
			want:     false,
		},
		{
			name: "stale decision within stale TTL can be used",
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				CreatedAt:        time.Now().Add(-40 * time.Second),
				ExpiresAt:        time.Now().Add(-10 * time.Second),
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
			},
			want: true, // Can use within stale TTL
		},
		{
			name: "stale decision beyond stale TTL cannot be used",
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				CreatedAt:        time.Now().Add(-2 * time.Hour),
				ExpiresAt:        time.Now().Add(-1 * time.Hour),
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
			},
			want: false, // Too stale
		},
		{
			name: "active decision can be used",
			decision: &Decision{
				Allow:            true,
				Reason:           "Allowed",
				CreatedAt:        time.Now(),
				ExpiresAt:        time.Now().Add(10 * time.Minute),
				EvaluatorVersion: "v1",
				PolicyVersion:    "v1",
				ParserVersion:    "v1",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checker.CanUseStale(tt.decision)
			if got != tt.want {
				t.Errorf("CanUseStale() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// Invalidation Event Tests
// =============================================================================

func TestInvalidationEvent(t *testing.T) {
	now := time.Now()

	// Set time for testing
	timeNow = func() time.Time { return now }
	defer func() { timeNow = time.Now }()

	tests := []struct {
		name  string
		event InvalidationEvent
	}{
		{
			name: "policy invalidation",
			event: InvalidationEvent{
				Type:          InvalidationTypePolicy,
				PolicyVersion: "v1",
				Timestamp:     now,
			},
		},
		{
			name: "resource invalidation",
			event: InvalidationEvent{
				Type:      InvalidationTypeResource,
				Resource:  "https://example.com/resource",
				Timestamp: now,
			},
		},
		{
			name: "agent invalidation",
			event: InvalidationEvent{
				Type:      InvalidationTypeAgent,
				Agent:     "https://example.com/webid#me",
				Timestamp: now,
			},
		},
		{
			name: "clear invalidation",
			event: InvalidationEvent{
				Type:      InvalidationTypeClear,
				Timestamp: now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the event can be created
			if tt.event.Timestamp != now {
				t.Errorf("Expected timestamp %v, got %v", now, tt.event.Timestamp)
			}
		})
	}
}

// Helper for testing time-dependent behavior
var timeNow = time.Now
