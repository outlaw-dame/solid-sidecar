package authn

import (
	"fmt"
	"testing"
	"time"
)

func TestReplayCacheRejectsDuplicateUntilExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	cache := NewReplayCacheWithConfig(ReplayCacheConfig{
		MaxEntries: 100,
		Now:        func() time.Time { return now },
	})
	if !cache.Store("proof", now.Add(time.Minute)) {
		t.Fatal("first store should succeed")
	}
	if cache.Store("proof", now.Add(time.Minute)) {
		t.Fatal("duplicate proof should be rejected")
	}
	now = now.Add(2 * time.Minute)
	cache.config.Now = func() time.Time { return now }
	if !cache.Store("proof", now.Add(time.Minute)) {
		t.Fatal("expired proof should be accepted again")
	}
}

func TestReplayCacheEvictsWhenFull(t *testing.T) {
	now := time.Unix(100, 0)
	// Create a cache with max 10 entries
	cache := NewReplayCacheWithConfig(ReplayCacheConfig{
		MaxEntries: 10,
		Now:        func() time.Time { return now },
	})

	// Fill the cache
	for i := 0; i < 10; i++ {
		if !cache.Store(fmt.Sprintf("proof-%d", i), now.Add(time.Minute)) {
			t.Fatalf("store %d should succeed", i)
		}
	}

	// Cache should be full
	if cache.Size() != 10 {
		t.Fatalf("expected cache size 10, got %d", cache.Size())
	}

	// Next store should trigger eviction and succeed
	if !cache.Store("proof-new", now.Add(time.Minute)) {
		t.Fatal("store should succeed after eviction")
	}

	// Cache should still have 10 entries (one was evicted)
	if cache.Size() != 10 {
		t.Fatalf("expected cache size 10 after eviction, got %d", cache.Size())
	}
}

func TestReplayCacheWithZeroMaxEntriesUsesDefault(t *testing.T) {
	cache := NewReplayCacheWithConfig(ReplayCacheConfig{
		MaxEntries: 0, // Should use default
		Now:        time.Now,
	})
	// Should not panic and should use default max entries
	for i := 0; i < 100; i++ {
		cache.Store(fmt.Sprintf("proof-%d", i), time.Now().Add(time.Minute))
	}
	if cache.Size() != 100 {
		t.Fatalf("expected 100 entries, got %d", cache.Size())
	}
}
