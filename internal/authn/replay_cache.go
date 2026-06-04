package authn

import (
	"sync"
	"time"
)

type ReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	now     func() time.Time
}

func NewReplayCache() *ReplayCache {
	return &ReplayCache{
		entries: make(map[string]time.Time),
		now:     time.Now,
	}
}

// Store records key until expiresAt. It returns false when key already exists
// and has not expired.
func (c *ReplayCache) Store(key string, expiresAt time.Time) bool {
	if key == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	for k, expires := range c.entries {
		if !expires.After(now) {
			delete(c.entries, k)
		}
	}
	if expires, ok := c.entries[key]; ok && expires.After(now) {
		return false
	}
	if !expiresAt.After(now) {
		expiresAt = now.Add(time.Minute)
	}
	c.entries[key] = expiresAt
	return true
}
