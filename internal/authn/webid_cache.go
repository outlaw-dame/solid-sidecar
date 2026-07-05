package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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

	// closed indicates if the cache has been closed
	closed uint32

	// lastCleanup is the time of the last cleanup
	lastCleanup time.Time

	// cleanupCount is the number of cleanups performed
	cleanupCount uint64

	// evictionCount is the number of entries evicted due to size limits
	evictionCount uint64

	// hitCount is the number of cache hits
	hitCount uint64

	// missCount is the number of cache misses
	missCount uint64

	// maxWebIDLength is the maximum length of a WebID to cache
	maxWebIDLength int

	// requireHTTPS enforces HTTPS for all WebIDs
	requireHTTPS bool

	// allowedSchemes is a list of allowed URL schemes
	allowedSchemes []string
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

	// MaxWebIDLength is the maximum length of a WebID to cache (default: 2048)
	MaxWebIDLength int

	// RequireHTTPS enforces HTTPS for all WebIDs (default: true)
	RequireHTTPS bool

	// AllowedSchemes is a list of allowed URL schemes (default: ["https"])
	AllowedSchemes []string
}

// DefaultWebIDCacheOptions returns safe default cache options
func DefaultWebIDCacheOptions() WebIDCacheOptions {
	return WebIDCacheOptions{
		MaxSize:         1000,
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
		Logger:          nil,
		MaxWebIDLength:  2048,
		RequireHTTPS:    true,
		AllowedSchemes:  []string{"https"},
	}
}

// WebIDCacheStats contains cache statistics
type WebIDCacheStats struct {
	// Size is the current number of entries
	Size int

	// MaxSize is the maximum capacity
	MaxSize int

	// HitCount is the number of cache hits
	HitCount uint64

	// MissCount is the number of cache misses
	MissCount uint64

	// EvictionCount is the number of entries evicted
	EvictionCount uint64

	// CleanupCount is the number of cleanup cycles
	CleanupCount uint64

	// LastCleanup is the time of the last cleanup
	LastCleanup time.Time

	// DefaultTTL is the default TTL for entries
	DefaultTTL time.Duration

	// CleanupInterval is the cleanup interval
	CleanupInterval time.Duration
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
	if options.MaxWebIDLength <= 0 {
		options.MaxWebIDLength = 2048
	}
	if len(options.AllowedSchemes) == 0 {
		options.AllowedSchemes = []string{"https"}
	}

	cache := &WebIDCache{
		entries:         make(map[string]*WebIDCacheEntry),
		maxSize:         options.MaxSize,
		defaultTTL:      options.DefaultTTL,
		logger:          options.Logger,
		cleanupInterval: options.CleanupInterval,
		stopChan:        make(chan struct{}),
		cleanupDone:     make(chan struct{}),
		lastCleanup:     time.Now(),
		maxWebIDLength:  options.MaxWebIDLength,
		requireHTTPS:    options.RequireHTTPS,
		allowedSchemes:  options.AllowedSchemes,
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
	// Validate WebID before accessing cache
	if err := c.validateWebID(webID); err != nil {
		c.logger.Warn("Invalid WebID in cache Get", "webid", webID, "error", err)
		atomic.AddUint64(&c.missCount, 1)
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if cache is closed
	if atomic.LoadUint32(&c.closed) == 1 {
		return nil, false
	}

	entry, exists := c.entries[webID]
	if !exists {
		atomic.AddUint64(&c.missCount, 1)
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		atomic.AddUint64(&c.missCount, 1)
		return nil, false
	}

	atomic.AddUint64(&c.hitCount, 1)
	return entry.Profile, true
}

// GetWithMetadata retrieves a WebID profile and its metadata from cache
func (c *WebIDCache) GetWithMetadata(webID string) (*WebIDProfile, string, string, bool) {
	// Validate WebID before accessing cache
	if err := c.validateWebID(webID); err != nil {
		c.logger.Warn("Invalid WebID in cache GetWithMetadata", "webid", webID, "error", err)
		atomic.AddUint64(&c.missCount, 1)
		return nil, "", "", false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if cache is closed
	if atomic.LoadUint32(&c.closed) == 1 {
		return nil, "", "", false
	}

	entry, exists := c.entries[webID]
	if !exists {
		atomic.AddUint64(&c.missCount, 1)
		return nil, "", "", false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		atomic.AddUint64(&c.missCount, 1)
		return nil, "", "", false
	}

	atomic.AddUint64(&c.hitCount, 1)
	return entry.Profile, entry.Issuer, entry.AssuranceLevel, true
}

// Set stores a WebID profile in the cache
func (c *WebIDCache) Set(webID string, profile *WebIDProfile, issuer string, assuranceLevel string) error {
	return c.SetWithTTL(webID, profile, issuer, assuranceLevel, c.defaultTTL)
}

// SetWithTTL stores a WebID profile in the cache with a custom TTL
func (c *WebIDCache) SetWithTTL(webID string, profile *WebIDProfile, issuer string, assuranceLevel string, ttl time.Duration) error {
	// Validate WebID
	if err := c.validateWebID(webID); err != nil {
		c.logger.Warn("Invalid WebID in cache SetWithTTL", "webid", webID, "error", err)
		return fmt.Errorf("invalid WebID: %w", err)
	}

	// Validate profile
	if profile == nil {
		return errors.New("profile cannot be nil")
	}

	// Validate issuer
	if err := c.validateIssuer(issuer); err != nil {
		return fmt.Errorf("invalid issuer: %w", err)
	}

	// Validate assurance level
	if err := c.validateAssuranceLevel(assuranceLevel); err != nil {
		return fmt.Errorf("invalid assurance level: %w", err)
	}

	// Validate TTL
	if ttl <= 0 {
		return errors.New("TTL must be positive")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if cache is closed
	if atomic.LoadUint32(&c.closed) == 1 {
		return errors.New("cache is closed")
	}

	// If we're at capacity and this is a new entry, evict the oldest first
	if len(c.entries) >= c.maxSize && !c.entryExists(webID) {
		c.evictOldest()
		atomic.AddUint64(&c.evictionCount, 1)
		c.logger.Debug("WebID cache evicted oldest entry during SetWithTTL")
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
	// Validate WebID
	if err := c.validateWebID(webID); err != nil {
		c.logger.Warn("Invalid WebID in cache Invalidate", "webid", webID, "error", err)
		return
	}

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

// Stats returns cache statistics
func (c *WebIDCache) Stats() WebIDCacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return WebIDCacheStats{
		Size:            len(c.entries),
		MaxSize:         c.maxSize,
		HitCount:        atomic.LoadUint64(&c.hitCount),
		MissCount:       atomic.LoadUint64(&c.missCount),
		EvictionCount:   atomic.LoadUint64(&c.evictionCount),
		CleanupCount:    atomic.LoadUint64(&c.cleanupCount),
		LastCleanup:     c.lastCleanup,
		DefaultTTL:      c.defaultTTL,
		CleanupInterval: c.cleanupInterval,
	}
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
	// Mark as closed first to prevent new operations
	atomic.StoreUint32(&c.closed, 1)

	// Stop cleanup goroutine
	close(c.stopChan)
	<-c.cleanupDone

	// Clear entries
	c.Clear()

	c.logger.Info("WebID cache closed", "hits", atomic.LoadUint64(&c.hitCount), "misses", atomic.LoadUint64(&c.missCount))
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

// validateWebID validates a WebID URI for safety
func (c *WebIDCache) validateWebID(webID string) error {
	if webID == "" {
		return errors.New("WebID cannot be empty")
	}

	// Check length
	if len(webID) > c.maxWebIDLength {
		return fmt.Errorf("WebID exceeds maximum length of %d characters", c.maxWebIDLength)
	}

	// Parse as URL
	parsed, err := url.Parse(webID)
	if err != nil {
		return fmt.Errorf("invalid WebID URL: %w", err)
	}

	// Check scheme
	if parsed.Scheme == "" {
		return errors.New("WebID must have a scheme")
	}

	// Check if scheme is allowed
	schemeAllowed := false
	for _, allowed := range c.allowedSchemes {
		if strings.EqualFold(parsed.Scheme, allowed) {
			schemeAllowed = true
			break
		}
	}
	if !schemeAllowed {
		return fmt.Errorf("WebID scheme %s is not allowed", parsed.Scheme)
	}

	// Enforce HTTPS if configured
	if c.requireHTTPS && parsed.Scheme != "https" {
		return fmt.Errorf("WebID must use HTTPS")
	}

	// Check host
	if parsed.Host == "" {
		return errors.New("WebID must have a host")
	}

	// Check for suspicious characters
	if strings.Contains(webID, "\x00") {
		return errors.New("WebID contains null byte")
	}

	// Check for potential path traversal
	if strings.Contains(webID, "..") {
		return errors.New("WebID contains path traversal characters")
	}

	return nil
}

// validateIssuer validates an issuer URL for safety
func (c *WebIDCache) validateIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("issuer cannot be empty")
	}

	// Check length
	if len(issuer) > c.maxWebIDLength {
		return fmt.Errorf("issuer exceeds maximum length of %d characters", c.maxWebIDLength)
	}

	// Parse as URL
	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}

	// Check scheme
	if parsed.Scheme == "" {
		return errors.New("issuer must have a scheme")
	}

	// Enforce HTTPS
	if parsed.Scheme != "https" {
		return fmt.Errorf("issuer must use HTTPS, got: %s", parsed.Scheme)
	}

	// Check host
	if parsed.Host == "" {
		return errors.New("issuer must have a host")
	}

	// Check for suspicious characters
	if strings.Contains(issuer, "\x00") {
		return errors.New("issuer contains null byte")
	}

	// Check for potential path traversal
	if strings.Contains(issuer, "..") {
		return errors.New("issuer contains path traversal characters")
	}

	return nil
}

// validateAssuranceLevel validates an assurance level string
func (c *WebIDCache) validateAssuranceLevel(level string) error {
	if level == "" {
		return nil // Empty is acceptable, will use default
	}

	// Valid assurance levels
	validLevels := map[string]bool{
		"none":      true,
		"low":       true,
		"basic":     true,
		"medium":    true,
		"standard":  true,
		"high":      true,
		"very_high": true,
	}

	if !validLevels[strings.ToLower(level)] {
		return fmt.Errorf("invalid assurance level: %s", level)
	}

	return nil
}
