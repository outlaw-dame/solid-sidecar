// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/authz/cache"
)

var ErrCachingEvaluatorNotConfigured = errors.New("caching evaluator not properly configured")

// CachingEvaluator wraps an Evaluator with a decision cache.
// It provides smart invalidation based on policy versions and resource changes.
type CachingEvaluator struct {
	// evaluator is the underlying evaluator to use for actual evaluation
	evaluator Evaluator

	// decisionCache is the cache for authorization decisions
	decisionCache cache.Cache

	// policyChangeNotifier receives notifications about policy changes
	// This is used for smart invalidation
	policyChangeNotifier PolicyChangeNotifier

	// options configure the caching behavior
	options CachingEvaluatorOptions

	// mu protects the evaluator configuration
	mu sync.RWMutex

	// logger is used for logging cache operations
	logger *slog.Logger
}

// PolicyChangeNotifier is an interface for receiving policy change notifications
type PolicyChangeNotifier interface {
	// SubscribePolicyChanges subscribes to policy change events
	SubscribePolicyChanges() <-chan PolicyChangeEvent
	// Close closes the subscription
	Close() error
}

// PolicyChangeEvent represents a policy change that may require cache invalidation
type PolicyChangeEvent struct {
	// ResourceURI is the URI of the resource whose policy changed
	ResourceURI string
	// PolicyURI is the URI of the policy that changed
	PolicyURI string
	// PolicyVersion is the new version/hash of the policy
	PolicyVersion string
	// OldPolicyVersion is the previous version/hash of the policy
	OldPolicyVersion string
	// ChangeType describes the type of change (create, update, delete)
	ChangeType PolicyChangeType
	// Timestamp is when the change occurred
	Timestamp time.Time
}

// PolicyChangeType represents the type of policy change
type PolicyChangeType string

const (
	PolicyChangeTypeCreate PolicyChangeType = "create"
	PolicyChangeTypeUpdate PolicyChangeType = "update"
	PolicyChangeTypeDelete PolicyChangeType = "delete"
)

// CachingEvaluatorOptions configures the caching evaluator
type CachingEvaluatorOptions struct {
	// CacheConfig is the configuration for the decision cache
	CacheConfig cache.Config

	// EnableCaching controls whether caching is enabled
	// Default: true
	EnableCaching bool

	// CacheTTL is the default TTL for cached decisions (overrides CacheConfig.TTL if set)
	// Default: 0 (use CacheConfig.TTL)
	CacheTTL time.Duration

	// MaxCacheTTL is the maximum TTL for cached decisions (overrides CacheConfig.MaxTTL if set)
	// Default: 0 (use CacheConfig.MaxTTL)
	MaxCacheTTL time.Duration

	// EnableNegativeCache controls whether negative (deny) decisions are cached
	// Default: false (for safety)
	EnableNegativeCache bool

	// NegativeCacheTTL is the TTL for negative decisions
	// Default: 1 minute
	NegativeCacheTTL time.Duration

	// SmartInvalidationEnabled controls whether smart invalidation is enabled
	// When enabled, the evaluator will automatically invalidate cache entries
	// when policy changes are detected
	// Default: true
	SmartInvalidationEnabled bool

	// BackgroundInvalidationInterval is how often to check for stale entries
	// Default: 1 minute
	BackgroundInvalidationInterval time.Duration

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultCachingEvaluatorOptions returns options with sensible defaults
func DefaultCachingEvaluatorOptions() CachingEvaluatorOptions {
	return CachingEvaluatorOptions{
		CacheConfig:                    cache.DefaultConfig(),
		EnableCaching:                  true,
		CacheTTL:                       0,
		MaxCacheTTL:                    0,
		EnableNegativeCache:            false,
		NegativeCacheTTL:               1 * time.Minute,
		SmartInvalidationEnabled:       true,
		BackgroundInvalidationInterval: 1 * time.Minute,
		Logger:                         nil,
	}
}

// NewCachingEvaluator creates a new caching evaluator that wraps an existing evaluator
func NewCachingEvaluator(
	evaluator Evaluator,
	options CachingEvaluatorOptions,
	notifier PolicyChangeNotifier,
) (*CachingEvaluator, error) {
	if evaluator == nil {
		return nil, fmt.Errorf("%w: evaluator is required", ErrCachingEvaluatorNotConfigured)
	}

	// Set defaults
	if options.Logger == nil {
		options.Logger = slog.Default()
	}

	// Create the decision cache
	cacheImpl, err := cache.NewMemoryCache(options.CacheConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create decision cache: %w", err)
	}

	// Apply cache TTL overrides
	if options.CacheTTL > 0 {
		options.CacheConfig.TTL = options.CacheTTL
	}
	if options.MaxCacheTTL > 0 {
		options.CacheConfig.MaxTTL = options.MaxCacheTTL
	}
	options.CacheConfig.EnableNegativeCache = options.EnableNegativeCache
	options.CacheConfig.NegativeCacheTTL = options.NegativeCacheTTL

	// Recreate cache with updated config
	cacheImpl, err = cache.NewMemoryCache(options.CacheConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create decision cache with updated config: %w", err)
	}

	cachingEval := &CachingEvaluator{
		evaluator:            evaluator,
		decisionCache:        cacheImpl,
		policyChangeNotifier: notifier,
		options:              options,
		logger:               options.Logger.With("component", "caching_evaluator"),
	}

	// Start background invalidation if enabled
	if options.SmartInvalidationEnabled && options.BackgroundInvalidationInterval > 0 {
		go cachingEval.startBackgroundInvalidation()
	}

	// Start policy change listener if notifier is provided
	if notifier != nil && options.SmartInvalidationEnabled {
		go cachingEval.listenForPolicyChanges()
	}

	options.Logger.Info("Caching evaluator initialized",
		"caching_enabled", options.EnableCaching,
		"smart_invalidation_enabled", options.SmartInvalidationEnabled,
		"cache_ttl", options.CacheConfig.TTL,
		"max_cache_size", options.CacheConfig.MaxSize,
	)

	return cachingEval, nil
}

// Evaluate implements the Evaluator interface with caching
func (e *CachingEvaluator) Evaluate(ctx context.Context, request Request) (Decision, error) {
	e.mu.RLock()
	EnableCaching := e.options.EnableCaching
	cache := e.decisionCache
	e.mu.RUnlock()

	// If caching is disabled, just use the underlying evaluator
	if !EnableCaching {
		return e.evaluator.Evaluate(ctx, request)
	}

	// Create cache key from the request
	cacheKey := e.createCacheKey(request)

	// Try to get from cache first
	cachedDecision, found := cache.Get(ctx, cacheKey)
	if found {
		e.logger.Debug("Cache hit for request",
			"request_id", request.RequestID,
			"resource", request.ResourceURI,
			"stale", cachedDecision.Stale,
		)

		// Convert cache.Decision to authz.Decision
		decision := e.convertFromCacheDecision(*cachedDecision, request)

		// If not stale, return the cached decision
		if !cachedDecision.Stale {
			e.logger.Debug("Returning cached decision",
				"request_id", request.RequestID,
				"decision", decision.Decision,
			)
			return decision, nil
		}

		// If stale, we might still use it (stale-while-revalidate)
		// but we'll also trigger a background refresh
		e.logger.Debug("Returning stale cached decision, triggering background refresh",
			"request_id", request.RequestID,
		)
		go e.refreshCacheInBackground(ctx, request, cacheKey)
		return decision, nil
	}

	// Cache miss - evaluate with the underlying evaluator
	e.logger.Debug("Cache miss, evaluating request",
		"request_id", request.RequestID,
		"resource", request.ResourceURI,
	)

	decision, err := e.evaluator.Evaluate(ctx, request)
	if err != nil {
		return Decision{}, fmt.Errorf("evaluation failed: %w", err)
	}

	// Store the decision in cache
	if err := e.cacheDecision(ctx, cacheKey, decision); err != nil {
		e.logger.Warn("Failed to cache decision",
			"request_id", request.RequestID,
			"error", err,
		)
		// Don't fail the evaluation just because caching failed
		return decision, nil
	}

	return decision, nil
}

// createCacheKey creates a cache key from a request
func (e *CachingEvaluator) createCacheKey(request Request) *cache.CacheKey {
	// Get the primary mode from requested modes
	primaryMode := AccessModeRead
	if len(request.RequestedModes) > 0 {
		primaryMode = request.RequestedModes[0]
	}

	return &cache.CacheKey{
		Agent:            request.AgentWebID,
		DID:              request.Issuer, // Using Issuer as DID for compatibility
		Client:           request.ClientID,
		Method:           request.Method,
		Mode:             string(primaryMode),
		Resource:         request.ResourceURI,
		PolicyVersion:    request.PolicyVersion,
		ParserVersion:    request.ParserVersion,
		EvaluatorVersion: request.EvaluatorVersion,
	}
}

// convertFromCacheDecision converts a cache.Decision to authz.Decision
func (e *CachingEvaluator) convertFromCacheDecision(cacheDecision cache.Decision, request Request) Decision {
	// Map cache decision to authz decision
	var decisionValue DecisionValue
	if cacheDecision.Allow {
		decisionValue = DecisionAllow
	} else {
		decisionValue = DecisionDeny
	}

	// Create audit fields for the decision
	audit := AuditForRequest(request)

	return Decision{
		SchemaVersion:   SchemaVersion,
		RequestID:       request.RequestID,
		Decision:        decisionValue,
		ReasonCode:      ReasonCachedDecision,
		StatusHint:      0,
		CacheTTLSeconds: int(cacheDecision.ExpiresAt.Sub(cacheDecision.CreatedAt).Seconds()),
		PolicyVersion:   cacheDecision.PolicyVersion,
		ResourceVersion: request.ResourceVersion,
		Audit:           audit,
	}
}

// cacheDecision stores a decision in the cache
func (e *CachingEvaluator) cacheDecision(ctx context.Context, key *cache.CacheKey, decision Decision) error {
	// Convert authz.Decision to cache.Decision
	cacheDecision := e.convertToCacheDecision(decision)

	return e.decisionCache.Put(ctx, key, &cacheDecision)
}

// convertToCacheDecision converts an authz.Decision to cache.Decision
func (e *CachingEvaluator) convertToCacheDecision(decision Decision) cache.Decision {
	// Determine if this is an allow or deny decision
	allow := decision.Decision == DecisionAllow

	// Calculate TTL from CacheTTLSeconds
	ttl := time.Duration(decision.CacheTTLSeconds) * time.Second
	if ttl == 0 {
		ttl = e.options.CacheConfig.TTL
	}

	now := time.Now()

	return cache.Decision{
		Allow:            allow,
		Reason:           string(decision.ReasonCode),
		Stale:            false,
		EvaluatorVersion: SchemaVersion, // Using schema version as evaluator version
		PolicyVersion:    decision.PolicyVersion,
		ParserVersion:    "", // Parser version not available in Decision
		CreatedAt:        now,
		ExpiresAt:        now.Add(ttl),
	}
}

// InvalidatePolicy invalidates all cached decisions for a specific policy version
func (e *CachingEvaluator) InvalidatePolicy(ctx context.Context, policyVersion string) error {
	return e.decisionCache.InvalidatePolicy(ctx, policyVersion)
}

// InvalidateResource invalidates all cached decisions for a specific resource
func (e *CachingEvaluator) InvalidateResource(ctx context.Context, resource string) error {
	return e.decisionCache.InvalidateResource(ctx, resource)
}

// InvalidateAgent invalidates all cached decisions for a specific agent
func (e *CachingEvaluator) InvalidateAgent(ctx context.Context, agent string) error {
	return e.decisionCache.InvalidateAgent(ctx, agent)
}

// ClearCache clears all cached decisions
func (e *CachingEvaluator) ClearCache(ctx context.Context) error {
	return e.decisionCache.Clear(ctx)
}

// GetCacheMetrics returns the current cache metrics
func (e *CachingEvaluator) GetCacheMetrics() cache.MetricsSnapshot {
	return e.decisionCache.Metrics()
}

// IsCachingEnabled returns true if caching is enabled
func (e *CachingEvaluator) IsCachingEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.options.EnableCaching
}

// EnableCaching enables or disables caching
func (e *CachingEvaluator) EnableCaching(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.options.EnableCaching = enabled
	e.logger.Info("Caching state changed", "enabled", enabled)
}

// listenForPolicyChanges listens for policy change events and invalidates cache accordingly
func (e *CachingEvaluator) listenForPolicyChanges() {
	if e.policyChangeNotifier == nil {
		return
	}

	subscription := e.policyChangeNotifier.SubscribePolicyChanges()
	defer e.policyChangeNotifier.Close()

	ctx := context.Background()
	for event := range subscription {
		e.logger.Debug("Received policy change event",
			"change_type", event.ChangeType,
			"policy_uri", event.PolicyURI,
			"resource_uri", event.ResourceURI,
			"old_version", event.OldPolicyVersion,
			"new_version", event.PolicyVersion,
		)

		// Invalidate based on the change type
		switch event.ChangeType {
		case PolicyChangeTypeCreate, PolicyChangeTypeUpdate:
			// Invalidate entries for the specific policy version
			if event.OldPolicyVersion != "" {
				if err := e.InvalidatePolicy(ctx, event.OldPolicyVersion); err != nil {
					e.logger.Error("Failed to invalidate old policy version",
						"old_version", event.OldPolicyVersion,
						"error", err,
					)
				}
			}
			// Also invalidate by resource to be safe
			if event.ResourceURI != "" {
				if err := e.InvalidateResource(ctx, event.ResourceURI); err != nil {
					e.logger.Error("Failed to invalidate resource",
						"resource", event.ResourceURI,
						"error", err,
					)
				}
			}

		case PolicyChangeTypeDelete:
			// Invalidate entries for the deleted policy
			if event.PolicyVersion != "" {
				if err := e.InvalidatePolicy(ctx, event.PolicyVersion); err != nil {
					e.logger.Error("Failed to invalidate deleted policy",
						"version", event.PolicyVersion,
						"error", err,
					)
				}
			}
			// Also invalidate by resource
			if event.ResourceURI != "" {
				if err := e.InvalidateResource(ctx, event.ResourceURI); err != nil {
					e.logger.Error("Failed to invalidate resource for deleted policy",
						"resource", event.ResourceURI,
						"error", err,
					)
				}
			}

		default:
			e.logger.Warn("Unknown policy change type", "type", event.ChangeType)
		}
	}
}

// startBackgroundInvalidation starts a background goroutine to periodically check for stale entries
func (e *CachingEvaluator) startBackgroundInvalidation() {
	interval := e.options.BackgroundInvalidationInterval
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	ctx := context.Background()
	for range ticker.C {
		// Check for stale entries and proactively invalidate
		e.checkForStaleEntries(ctx)
	}
}

// checkForStaleEntries checks for stale cache entries and invalidates them
func (e *CachingEvaluator) checkForStaleEntries(ctx context.Context) {
	// Get current metrics
	metrics := e.decisionCache.Metrics()

	// If there are stale hits, we might want to proactively invalidate
	if metrics.StaleHits > 0 {
		e.logger.Info("Detected stale cache entries, triggering proactive invalidation",
			"stale_hits", metrics.StaleHits,
			"total_hits", metrics.Hits,
		)
		// For now, we'll just log this
		// In a production implementation, we could track which entries are stale
		// and invalidate them proactively
	}
}

// refreshCacheInBackground refreshes a cache entry in the background
func (e *CachingEvaluator) refreshCacheInBackground(ctx context.Context, request Request, key *cache.CacheKey) {
	// Evaluate the request to get a fresh decision
	decision, err := e.evaluator.Evaluate(ctx, request)
	if err != nil {
		e.logger.Error("Background cache refresh failed",
			"request_id", request.RequestID,
			"error", err,
		)
		return
	}

	// Store the fresh decision in cache
	if err := e.cacheDecision(ctx, key, decision); err != nil {
		e.logger.Error("Background cache refresh failed to store decision",
			"request_id", request.RequestID,
			"error", err,
		)
	}
}

// Ensure CachingEvaluator implements Evaluator interface
var _ Evaluator = (*CachingEvaluator)(nil)
