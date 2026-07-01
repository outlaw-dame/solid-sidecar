// Package cache implements a decision cache for authorization decisions.
// This cache is designed to make authorization fast enough for a modern scalable Solid runtime
// while maintaining correctness, safety, and privacy.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Decision represents an authorization decision with associated metadata.
// This structure allows for proper cache invalidation and stale decision handling.
type Decision struct {
	// Allow is true if the request is allowed, false if denied.
	Allow bool
	// Reason provides a privacy-safe explanation for the decision.
	// This should not contain sensitive information like WebIDs, resource contents, or policy bodies.
	Reason string
	// Stale indicates whether this decision is stale and should be re-evaluated.
	Stale bool
	// EvaluatorVersion is the version of the evaluator that produced this decision.
	EvaluatorVersion string
	// PolicyVersion is the version/hash of the policy that was used.
	PolicyVersion string
	// ParserVersion is the version of the parser that was used.
	ParserVersion string
	// CreatedAt is when this decision was cached.
	CreatedAt time.Time
	// ExpiresAt is when this decision expires.
	ExpiresAt time.Time
}

// CacheKey represents the key for a cached decision.
// The key includes all factors that affect the authorization decision.
type CacheKey struct {
	// Agent is the identifier of the agent (e.g., WebID or DID).
	Agent string
	// DID is an optional DID identifier for the agent.
	DID string
	// Client is the client identifier.
	Client string
	// Method is the HTTP method (GET, POST, PUT, DELETE, etc.).
	Method string
	// Mode is the authorization mode (read, write, append, control).
	Mode string
	// Resource is the resource being accessed.
	Resource string
	// PolicyVersion is the version/hash of the policy.
	PolicyVersion string
	// ParserVersion is the version of the parser.
	ParserVersion string
	// EvaluatorVersion is the version of the evaluator.
	EvaluatorVersion string
}

// String returns a stable string representation of the cache key.
func (k *CacheKey) String() string {
	// Create a deterministic hash of the key components
	h := sha256.New()
	h.Write([]byte(k.Agent))
	h.Write([]byte("|"))
	h.Write([]byte(k.DID))
	h.Write([]byte("|"))
	h.Write([]byte(k.Client))
	h.Write([]byte("|"))
	h.Write([]byte(k.Method))
	h.Write([]byte("|"))
	h.Write([]byte(k.Mode))
	h.Write([]byte("|"))
	h.Write([]byte(k.Resource))
	h.Write([]byte("|"))
	h.Write([]byte(k.PolicyVersion))
	h.Write([]byte("|"))
	h.Write([]byte(k.ParserVersion))
	h.Write([]byte("|"))
	h.Write([]byte(k.EvaluatorVersion))
	return hex.EncodeToString(h.Sum(nil))
}

// CacheError represents errors that can occur during cache operations.
var (
	ErrCacheKeyRequired = errors.New("cache key is required")
	ErrDecisionRequired = errors.New("decision is required")
	ErrCachePoisoning   = errors.New("cache poisoning detected")
	ErrCacheExpiration  = errors.New("cache entry has expired")
	ErrNegativeCache    = errors.New("negative cache entry")
)

// Config holds the configuration for the decision cache.
type Config struct {
	// TTL is the default time-to-live for cache entries.
	TTL time.Duration
	// MaxTTL is the maximum time-to-live for cache entries.
	MaxTTL time.Duration
	// StaleTTL is the time after which entries are considered stale but may still be used.
	StaleTTL time.Duration
	// MaxSize is the maximum number of entries in the cache.
	MaxSize int
	// EnableNegativeCache controls whether negative (deny) decisions are cached.
	// This should be enabled carefully to avoid cache poisoning.
	EnableNegativeCache bool
	// NegativeCacheTTL is the TTL for negative decisions (must be <= TTL).
	NegativeCacheTTL time.Duration
}

// DefaultConfig returns a safe default configuration for the decision cache.
func DefaultConfig() Config {
	return Config{
		TTL:                 5 * time.Minute,
		MaxTTL:              1 * time.Hour,
		StaleTTL:            30 * time.Second,
		MaxSize:             10000,
		EnableNegativeCache: false, // Disabled by default for safety
		NegativeCacheTTL:    1 * time.Minute,
	}
}

// Validate validates the cache configuration.
func (cfg Config) Validate() error {
	if cfg.TTL <= 0 {
		return errors.New("TTL must be positive")
	}
	if cfg.MaxTTL <= 0 {
		return errors.New("MaxTTL must be positive")
	}
	if cfg.StaleTTL < 0 {
		return errors.New("StaleTTL must be non-negative")
	}
	if cfg.StaleTTL > cfg.TTL {
		return errors.New("StaleTTL cannot exceed TTL")
	}
	if cfg.MaxSize <= 0 {
		return errors.New("MaxSize must be positive")
	}
	if cfg.EnableNegativeCache && cfg.NegativeCacheTTL <= 0 {
		return errors.New("NegativeCacheTTL must be positive when negative cache is enabled")
	}
	if cfg.EnableNegativeCache && cfg.NegativeCacheTTL > cfg.TTL {
		return errors.New("NegativeCacheTTL cannot exceed TTL")
	}
	return nil
}

// Cache is the interface for authorization decision caching.
type Cache interface {
	// Get retrieves a cached decision for the given key.
	// Returns the decision and true if found, or nil and false if not found.
	Get(ctx context.Context, key *CacheKey) (*Decision, bool)
	// Put stores a decision in the cache with the given key.
	// Returns an error if the decision cannot be cached (e.g., invalid key, cache poisoning attempt).
	Put(ctx context.Context, key *CacheKey, decision *Decision) error
	// Invalidate removes all entries associated with a specific policy version.
	// This is called when a policy changes to ensure stale decisions are not used.
	InvalidatePolicy(ctx context.Context, policyVersion string) error
	// InvalidateResource removes all entries associated with a specific resource.
	InvalidateResource(ctx context.Context, resource string) error
	// InvalidateAgent removes all entries associated with a specific agent.
	InvalidateAgent(ctx context.Context, agent string) error
	// Clear removes all entries from the cache.
	Clear(ctx context.Context) error
	// Metrics returns the current cache metrics.
	Metrics() MetricsSnapshot
}

// MetricsSnapshot holds a snapshot of cache metrics.
type MetricsSnapshot struct {
	// Hit count
	Hits int64
	// Miss count
	Misses int64
	// Stale hit count (stale decisions that were used)
	StaleHits int64
	// Put count
	Puts int64
	// Put errors
	PutErrors int64
	// Invalidation count
	Invalidations int64
	// Eviction count (due to size limits)
	Evictions int64
	// Current size
	CurrentSize int
}

// MemoryCache is an in-memory implementation of the Cache interface.
// It is suitable for single-instance deployments.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	config  Config
	metrics MetricsSnapshot
}

type cacheEntry struct {
	key       *CacheKey
	decision  *Decision
	expiresAt time.Time
}

// NewMemoryCache creates a new in-memory cache with the given configuration.
func NewMemoryCache(cfg Config) (*MemoryCache, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid cache config: %w", err)
	}
	return &MemoryCache{
		entries: make(map[string]*cacheEntry),
		config:  cfg,
	}, nil
}

// Get retrieves a cached decision for the given key.
func (c *MemoryCache) Get(ctx context.Context, key *CacheKey) (*Decision, bool) {
	if key == nil {
		c.metrics.Misses++
		return nil, false
	}

	keyStr := key.String()

	c.mu.RLock()
	entry, exists := c.entries[keyStr]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		c.metrics.Misses++
		c.mu.Unlock()
		return nil, false
	}

	// Check if the entry has expired
	now := time.Now()
	if now.After(entry.expiresAt) {
		// Entry has expired, remove it
		c.mu.Lock()
		delete(c.entries, keyStr)
		c.metrics.Misses++
		c.mu.Unlock()
		return nil, false
	}

	// Check if the entry is stale
	stale := now.After(entry.decision.ExpiresAt) || now.After(entry.expiresAt.Add(-c.config.StaleTTL))

	c.mu.Lock()
	if stale {
		c.metrics.StaleHits++
	} else {
		c.metrics.Hits++
	}
	c.mu.Unlock()

	// Return a copy to prevent modification
	decisionCopy := *entry.decision
	return &decisionCopy, true
}

// Put stores a decision in the cache with the given key.
func (c *MemoryCache) Put(ctx context.Context, key *CacheKey, decision *Decision) error {
	if key == nil {
		c.mu.Lock()
		c.metrics.PutErrors++
		c.mu.Unlock()
		return ErrCacheKeyRequired
	}
	if decision == nil {
		c.mu.Lock()
		c.metrics.PutErrors++
		c.mu.Unlock()
		return ErrDecisionRequired
	}

	// Validate the decision for safety
	if err := validateDecision(decision); err != nil {
		c.mu.Lock()
		c.metrics.PutErrors++
		c.mu.Unlock()
		return fmt.Errorf("invalid decision: %w", err)
	}

	// Check for cache poisoning attempts
	if isCachePoisoningAttempt(key, decision) {
		c.mu.Lock()
		c.metrics.PutErrors++
		c.mu.Unlock()
		return ErrCachePoisoning
	}

	// Set expiration times
	now := time.Now()
	var ttl time.Duration
	if !decision.Allow && !c.config.EnableNegativeCache {
		// Don't cache negative decisions if negative cache is disabled
		return nil
	}

	if !decision.Allow {
		ttl = c.config.NegativeCacheTTL
	} else {
		ttl = c.config.TTL
	}

	// Cap TTL at MaxTTL
	if ttl > c.config.MaxTTL {
		ttl = c.config.MaxTTL
	}

	expiresAt := now.Add(ttl)
	decision.ExpiresAt = expiresAt

	// Create cache entry
	entry := &cacheEntry{
		key:       key,
		decision:  decision,
		expiresAt: expiresAt,
	}

	keyStr := key.String()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check size limit
	if len(c.entries) >= c.config.MaxSize {
		// Evict oldest entries (simple LRU-like eviction)
		c.evictOldest()
		c.metrics.Evictions++
	}

	c.entries[keyStr] = entry
	c.metrics.Puts++

	return nil
}

// evictOldest removes the oldest entries to make room for new ones.
func (c *MemoryCache) evictOldest() {
	// Simple eviction: remove entries until we're under the limit
	// In a production implementation, this would use a more sophisticated LRU algorithm
	for len(c.entries) >= c.config.MaxSize {
		// Find the oldest entry
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, entry := range c.entries {
			if first || entry.expiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = entry.expiresAt
				first = false
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
}

// InvalidatePolicy removes all entries associated with a specific policy version.
func (c *MemoryCache) InvalidatePolicy(ctx context.Context, policyVersion string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for keyStr, entry := range c.entries {
		if entry.key.PolicyVersion == policyVersion {
			delete(c.entries, keyStr)
			count++
		}
	}
	c.metrics.Invalidations += int64(count)
	return nil
}

// InvalidateResource removes all entries associated with a specific resource.
func (c *MemoryCache) InvalidateResource(ctx context.Context, resource string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for keyStr, entry := range c.entries {
		if entry.key.Resource == resource {
			delete(c.entries, keyStr)
			count++
		}
	}
	c.metrics.Invalidations += int64(count)
	return nil
}

// InvalidateAgent removes all entries associated with a specific agent.
func (c *MemoryCache) InvalidateAgent(ctx context.Context, agent string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for keyStr, entry := range c.entries {
		if entry.key.Agent == agent {
			delete(c.entries, keyStr)
			count++
		}
	}
	c.metrics.Invalidations += int64(count)
	return nil
}

// Clear removes all entries from the cache.
func (c *MemoryCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry)
	return nil
}

// Metrics returns the current cache metrics.
func (c *MemoryCache) Metrics() MetricsSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return MetricsSnapshot{
		Hits:          c.metrics.Hits,
		Misses:        c.metrics.Misses,
		StaleHits:     c.metrics.StaleHits,
		Puts:          c.metrics.Puts,
		PutErrors:     c.metrics.PutErrors,
		Invalidations: c.metrics.Invalidations,
		Evictions:     c.metrics.Evictions,
		CurrentSize:   len(c.entries),
	}
}

// validateDecision validates a decision for safety before caching.
func validateDecision(decision *Decision) error {
	// Check that the decision has reasonable values
	if decision.CreatedAt.IsZero() {
		return errors.New("decision must have a creation timestamp")
	}
	// Only validate ExpiresAt if it has been explicitly set (not zero)
	// The cache will set ExpiresAt based on TTL if it's zero
	if !decision.ExpiresAt.IsZero() && decision.ExpiresAt.Before(decision.CreatedAt) {
		return errors.New("expiration cannot be before creation")
	}
	// Check for suspiciously long reasons (potential information leakage)
	if len(decision.Reason) > 1024 {
		return errors.New("decision reason is too long")
	}
	return nil
}

// isCachePoisoningAttempt checks for potential cache poisoning patterns.
func isCachePoisoningAttempt(key *CacheKey, decision *Decision) bool {
	// Check for empty or suspicious keys
	if key.Agent == "" && key.DID == "" && key.Client == "" {
		return true
	}
	if key.Resource == "" {
		return true
	}
	if key.Method == "" {
		return true
	}

	// Check for decisions that are always allow with no reason
	if decision.Allow && decision.Reason == "" {
		// This could be legitimate, but it's suspicious
		// In a real implementation, this would require more context
	}

	// Check for decisions with very long TTLs
	if decision.ExpiresAt.Sub(decision.CreatedAt) > 24*time.Hour {
		return true
	}

	return false
}

// MultiInstanceCache is an interface for multi-instance cache coordination.
// This allows for distributed cache invalidation and consistency.
type MultiInstanceCache interface {
	Cache
	// PublishInvalidation publishes an invalidation event to other instances.
	PublishInvalidation(ctx context.Context, invalidation InvalidationEvent) error
	// SubscribeInvalidation subscribes to invalidation events from other instances.
	SubscribeInvalidation() <-chan InvalidationEvent
}

// InvalidationEvent represents a cache invalidation event.
type InvalidationEvent struct {
	// Type of invalidation
	Type InvalidationType
	// PolicyVersion is the version of the policy that was invalidated (if applicable)
	PolicyVersion string
	// Resource is the resource that was invalidated (if applicable)
	Resource string
	// Agent is the agent that was invalidated (if applicable)
	Agent string
	// Timestamp is when the invalidation occurred
	Timestamp time.Time
}

// InvalidationType represents the type of cache invalidation.
type InvalidationType string

const (
	InvalidationTypePolicy   InvalidationType = "policy"
	InvalidationTypeResource InvalidationType = "resource"
	InvalidationTypeAgent    InvalidationType = "agent"
	InvalidationTypeClear    InvalidationType = "clear"
)

// NewInvalidationEvent creates a new invalidation event.
func NewInvalidationEvent(invType InvalidationType, policyVersion, resource, agent string) InvalidationEvent {
	return InvalidationEvent{
		Type:          invType,
		PolicyVersion: policyVersion,
		Resource:      resource,
		Agent:         agent,
		Timestamp:     time.Now(),
	}
}

// StaleDecisionChecker provides functionality to check if a decision is stale.
type StaleDecisionChecker struct {
	config Config
}

// NewStaleDecisionChecker creates a new stale decision checker.
func NewStaleDecisionChecker(cfg Config) *StaleDecisionChecker {
	return &StaleDecisionChecker{config: cfg}
}

// IsStale checks if a decision is stale and should be re-evaluated.
func (s *StaleDecisionChecker) IsStale(decision *Decision) bool {
	if decision == nil {
		return true
	}
	now := time.Now()
	return now.After(decision.ExpiresAt) || now.After(decision.CreatedAt.Add(s.config.StaleTTL))
}

// CanUseStale checks if a stale decision can still be used (stale-while-revalidate).
func (s *StaleDecisionChecker) CanUseStale(decision *Decision) bool {
	if decision == nil {
		return false
	}
	now := time.Now()
	// Can use stale decisions within the stale TTL period
	return now.Before(decision.ExpiresAt.Add(s.config.StaleTTL))
}
