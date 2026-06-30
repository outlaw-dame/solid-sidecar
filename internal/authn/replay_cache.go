package authn

import (
	"sync"
	"time"
)

// DefaultReplayCacheMaxEntries is the default maximum number of entries in the replay cache
const DefaultReplayCacheMaxEntries = 10000

// ReplayCacheConfig holds configuration for the replay cache
type ReplayCacheConfig struct {
	MaxEntries int              // Maximum number of entries, 0 means unbounded (not recommended)
	Now        func() time.Time // Time provider for testing
}

// ReplayCache provides protection against DPoP proof replay attacks
type ReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	config  ReplayCacheConfig
}

// NewReplayCache creates a new replay cache with default configuration
func NewReplayCache() *ReplayCache {
	return NewReplayCacheWithConfig(ReplayCacheConfig{
		MaxEntries: DefaultReplayCacheMaxEntries,
		Now:        time.Now,
	})
}

// NewReplayCacheWithConfig creates a new replay cache with the given configuration
func NewReplayCacheWithConfig(config ReplayCacheConfig) *ReplayCache {
	if config.MaxEntries <= 0 {
		config.MaxEntries = DefaultReplayCacheMaxEntries
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &ReplayCache{
		entries: make(map[string]time.Time),
		config:  config,
	}
}

// Store records key until expiresAt. It returns false when key already exists
// and has not expired. If the cache is full, it evicts the oldest entries.
func (c *ReplayCache) Store(key string, expiresAt time.Time) bool {
	if key == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.config.Now()

	// First, remove expired entries
	for k, expires := range c.entries {
		if !expires.After(now) {
			delete(c.entries, k)
		}
	}

	// Check if key already exists and is not expired
	if expires, ok := c.entries[key]; ok && expires.After(now) {
		return false
	}

	// Adjust expiration if it's in the past
	if !expiresAt.After(now) {
		expiresAt = now.Add(time.Minute)
	}

	// Evict entries if we're at capacity
	maxEntries := c.config.MaxEntries
	if maxEntries > 0 && len(c.entries) >= maxEntries {
		// Simple eviction strategy: remove a portion of entries to make room
		// This is intentionally simple to avoid complexity and maintain performance
		// For production LRU cache, consider using a proper LRU implementation
		numToEvict := (maxEntries + 9) / 10 // Evict 10% of entries
		if numToEvict < 1 {
			numToEvict = 1
		}

		// Collect expired entries first
		var expiredKeys []string
		for k, expires := range c.entries {
			if !expires.After(now) {
				expiredKeys = append(expiredKeys, k)
			}
		}

		// If we have expired entries, remove them
		if len(expiredKeys) > 0 {
			for _, k := range expiredKeys {
				delete(c.entries, k)
			}
			// Check if we have room now
			if len(c.entries) < maxEntries {
				// Success, we have room
			} else {
				// Still need to evict more
				numToEvict = maxEntries - len(c.entries)
				if numToEvict < 1 {
					numToEvict = 1
				}
			}
		}

		// Evict arbitrary entries if still at capacity
		// This is a simple but effective strategy for a replay cache
		// where the exact eviction order doesn't matter as much
		if len(c.entries) >= maxEntries {
			count := 0
			for k := range c.entries {
				delete(c.entries, k)
				count++
				if count >= numToEvict {
					break
				}
			}
		}
	}

	c.entries[key] = expiresAt
	return true
}

// Size returns the current number of entries in the cache
func (c *ReplayCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Cleanup removes all expired entries from the cache and returns the count removed
func (c *ReplayCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.config.Now()
	count := 0
	for k, expires := range c.entries {
		if !expires.After(now) {
			delete(c.entries, k)
			count++
		}
	}
	return count
}
