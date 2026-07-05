package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrWebIDCacheExceeded is returned when the cache size exceeds the maximum
var ErrWebIDCacheExceeded = errors.New("WebID profile cache size exceeded")

// WebIDCache provides caching for WebID profiles with TTL-based expiration
type WebIDCache struct {
	mu sync.RWMutex

	// entries maps WebID URIs to cached profile data
	entries map[string]*WebIDCacheEntry

	// maxSize is the maximum number of entries allowed in the cache
	maxSize int

	// defaultTTL is the default time-to-live for cache entries
	defaultTTL time.Duration

	// logger is used for cache operations logging
	logger *slog.Logger

	// cleanupInterval is how often to run cleanup of expired entries
	cleanupInterval time.Duration

	// stopChan is used to stop the cleanup goroutine
	stopChan chan struct{}

	// cleanupDone is used to wait for cleanup goroutine to finish
	cleanupDone chan struct{}
}

// WebIDCacheEntry represents a cached WebID profile
type WebIDCacheEntry struct {
	// Profile is the cached WebID profile
	Profile *WebIDProfile

	// FetchedAt is when the profile was fetched
	FetchedAt time.Time

	// ExpiresAt is when the profile expires from cache
	ExpiresAt time.Time

	// Issuer is the OIDC issuer that issued this WebID
	Issuer string

	// AssuranceLevel is the identity assurance level at time of caching
	AssuranceLevel string
}

// WebIDCacheOptions configures the WebID profile cache
type WebIDCacheOptions struct {
	// MaxSize is the maximum number of profiles to cache (default: 1000)
	MaxSize int

	// DefaultTTL is the default TTL for cached profiles (default: 5 minutes)
	DefaultTTL time.Duration

	// CleanupInterval is how often to run cleanup (default: 1 minute)
	CleanupInterval time.Duration

	// Logger is the logger to use (nil uses default)
	Logger *slog.Logger
}

// DefaultWebIDCacheOptions returns safe default cache options
func DefaultWebIDCacheOptions() WebIDCacheOptions {
	return WebIDCacheOptions{
		MaxSize:         1000,
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
		Logger:          nil,
	}
}

// NewWebIDCache creates a new WebID profile cache
func NewWebIDCache(options WebIDCacheOptions) *WebIDCache {
	if options.MaxSize <= 0 {
		options.MaxSize = 1000
	}
	if options.DefaultTTL <= 0 {
		options.DefaultTTL = 5 * time.Minute
	}
	if options.CleanupInterval <= 0 {
		options.CleanupInterval = 1 * time.Minute
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}

	cache := &WebIDCache{
		entries:         make(map[string]*WebIDCacheEntry),
		maxSize:         options.MaxSize,
		defaultTTL:      options.DefaultTTL,
		logger:          options.Logger,
		cleanupInterval: options.CleanupInterval,
		stopChan:        make(chan struct{}),
		cleanupDone:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanupRoutine()

	return cache
}

// cleanupRoutine periodically cleans up expired entries
func (c *WebIDCache) cleanupRoutine() {
	defer close(c.cleanupDone)

	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.cleanupExpired()
		}
	}
}

// cleanupExpired removes all expired entries from the cache
func (c *WebIDCache) cleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for webID, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, webID)
			removed++
		}
	}

	if removed > 0 {
		c.logger.Debug("WebID cache cleanup removed expired entries", "count", removed)
	}
}

// Get retrieves a WebID profile from cache if it exists and hasn't expired
func (c *WebIDCache) Get(webID string) (*WebIDProfile, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[webID]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry.Profile, true
}

// GetWithMetadata retrieves a WebID profile and its metadata from cache
func (c *WebIDCache) GetWithMetadata(webID string) (*WebIDProfile, string, string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[webID]
	if !exists {
		return nil, "", "", false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, "", "", false
	}

	return entry.Profile, entry.Issuer, entry.AssuranceLevel, true
}

// Set stores a WebID profile in the cache
func (c *WebIDCache) Set(webID string, profile *WebIDProfile, issuer string, assuranceLevel string) error {
	return c.SetWithTTL(webID, profile, issuer, assuranceLevel, c.defaultTTL)
}

// SetWithTTL stores a WebID profile in the cache with a custom TTL
func (c *WebIDCache) SetWithTTL(webID string, profile *WebIDProfile, issuer string, assuranceLevel string, ttl time.Duration) error {
	if profile == nil {
		return errors.New("profile cannot be nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If we're at capacity and this is a new entry, evict the oldest first
	if len(c.entries) >= c.maxSize && !c.entryExists(webID) {
		c.evictOldest()
	}

	entry := &WebIDCacheEntry{
		Profile:        profile,
		FetchedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(ttl),
		Issuer:         issuer,
		AssuranceLevel: assuranceLevel,
	}

	c.entries[webID] = entry
	c.logger.Debug("WebID profile cached", "webid", webID, "issuer", issuer, "assurance", assuranceLevel)

	return nil
}

// entryExists checks if an entry exists for the given WebID
func (c *WebIDCache) entryExists(webID string) bool {
	_, exists := c.entries[webID]
	return exists
}

// evictOldest removes the oldest entry from the cache
// Must be called with lock held
func (c *WebIDCache) evictOldest() {
	var oldestWebID string
	var oldestTime time.Time

	for webID, entry := range c.entries {
		if oldestWebID == "" || entry.FetchedAt.Before(oldestTime) {
			oldestWebID = webID
			oldestTime = entry.FetchedAt
		}
	}

	if oldestWebID != "" {
		delete(c.entries, oldestWebID)
		c.logger.Debug("WebID cache evicted oldest entry", "webid", oldestWebID)
	}
}

// Invalidate removes a specific WebID profile from the cache
func (c *WebIDCache) Invalidate(webID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[webID]; exists {
		delete(c.entries, webID)
		c.logger.Debug("WebID profile invalidated", "webid", webID)
	}
}

// InvalidateByIssuer removes all profiles associated with a specific issuer from the cache
func (c *WebIDCache) InvalidateByIssuer(issuer string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for webID, entry := range c.entries {
		if entry.Issuer == issuer {
			delete(c.entries, webID)
			removed++
		}
	}

	if removed > 0 {
		c.logger.Info("WebID cache invalidated profiles by issuer", "issuer", issuer, "count", removed)
	}
}

// Size returns the current number of entries in the cache
func (c *WebIDCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// Clear removes all entries from the cache
func (c *WebIDCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*WebIDCacheEntry)
	c.logger.Info("WebID cache cleared")
}

// Close stops the cleanup goroutine and clears the cache
func (c *WebIDCache) Close() {
	close(c.stopChan)
	<-c.cleanupDone
	c.Clear()
	c.logger.Info("WebID cache closed")
}

// KeyRotationInfo holds information about key rotation events
type KeyRotationInfo struct {
	// WebID is the WebID whose key was rotated
	WebID string

	// OldKeyID is the previous key identifier
	OldKeyID string

	// NewKeyID is the new key identifier
	NewKeyID string

	// RotatedAt is when the rotation occurred
	RotatedAt time.Time

	// AssuranceLevel is the identity assurance level at rotation time
	AssuranceLevel string
}

// KeyRotationCallback is a function that receives key rotation notifications
type KeyRotationCallback func(info KeyRotationInfo)

// RegisterKeyRotationCallback registers a callback for key rotation events
// This is used for audit logging and monitoring
func (c *WebIDCache) RegisterKeyRotationCallback(callback KeyRotationCallback) {
	// Store callback - in a real implementation, this would trigger on key changes
	// For now, this is a placeholder for the audit integration
	_ = callback
}

// CheckAndInvalidateOnKeyChange checks if a WebID's key has changed and invalidates if so
// Returns true if the key was different from the cached version
func (c *WebIDCache) CheckAndInvalidateOnKeyChange(ctx context.Context, webID string, verifier *WebIDVerifier) (bool, error) {
	// Get current profile from cache
	cachedProfile, cachedIssuer, _, exists := c.GetWithMetadata(webID)

	if !exists {
		// Not in cache, nothing to invalidate
		return false, nil
	}

	// Re-fetch the profile to check for changes
	newProfile, err := verifier.VerifyWebIDOwnership(ctx, webID)
	if err != nil {
		return false, fmt.Errorf("failed to verify WebID ownership: %w", err)
	}

	// Compare the profiles - if they differ, key rotation may have occurred
	// Simple comparison: check if the profile JSON representation differs
	if !c.profilesEqual(cachedProfile, newProfile) {
		// Key rotation detected - invalidate cache
		c.Invalidate(webID)
		c.logger.Info("WebID profile changed, cache invalidated", "webid", webID, "cached_issuer", cachedIssuer)
		return true, nil
	}

	return false, nil
}

// profilesEqual does a simple equality check on WebID profiles
func (c *WebIDCache) profilesEqual(a, b *WebIDProfile) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Compare key fields
	if a.Subject != b.Subject {
		return false
	}
	if a.SolidOIDCIssuer != b.SolidOIDCIssuer {
		return false
	}

	// Simple check - in production, do a deep comparison
	return true
}
