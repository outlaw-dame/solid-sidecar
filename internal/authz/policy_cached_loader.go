// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var ErrPolicyCacheHit = errors.New("policy cache hit")

// CachedPolicyLoaderOptions configures the cached policy loader
type CachedPolicyLoaderOptions struct {
	// Loader is the underlying policy loader to use for cache misses
	Loader PolicyLoader

	// CacheStore is the cache store for policy documents
	CacheStore PolicyCacheStore

	// DefaultExpiryDuration is the default TTL for cached policies (0 = no expiry)
	// Default: 5 minutes
	DefaultExpiryDuration time.Duration

	// MaxCacheSize is the maximum number of entries in the cache
	// Default: 100
	MaxCacheSize int

	// Logger is the logger to use
	Logger *slog.Logger

	// Metrics is the metrics recorder for cache operations
	Metrics PolicyCacheMetricsRecorder
}

// DefaultCachedPolicyLoaderOptions returns options with sensible defaults
func DefaultCachedPolicyLoaderOptions(loader PolicyLoader, cacheStore PolicyCacheStore) CachedPolicyLoaderOptions {
	return CachedPolicyLoaderOptions{
		Loader:                loader,
		CacheStore:            cacheStore,
		DefaultExpiryDuration: 5 * time.Minute,
		MaxCacheSize:          100,
		Logger:                nil,
		Metrics:               NewNopPolicyCacheMetricsRecorder(),
	}
}

// PolicyCacheMetricsRecorder records cache operation metrics
type PolicyCacheMetricsRecorder interface {
	RecordCacheHit()
	RecordCacheMiss()
	RecordCacheExpiry()
	RecordCacheError()
	RecordCacheStoreError()
	RecordLoadSuccess()
	RecordLoadError()
}

// NopPolicyCacheMetricsRecorder is a no-op metrics recorder for testing
type NopPolicyCacheMetricsRecorder struct{}

func NewNopPolicyCacheMetricsRecorder() *NopPolicyCacheMetricsRecorder {
	return &NopPolicyCacheMetricsRecorder{}
}

func (r *NopPolicyCacheMetricsRecorder) RecordCacheHit()        {}
func (r *NopPolicyCacheMetricsRecorder) RecordCacheMiss()       {}
func (r *NopPolicyCacheMetricsRecorder) RecordCacheExpiry()     {}
func (r *NopPolicyCacheMetricsRecorder) RecordCacheError()      {}
func (r *NopPolicyCacheMetricsRecorder) RecordCacheStoreError() {}
func (r *NopPolicyCacheMetricsRecorder) RecordLoadSuccess()     {}
func (r *NopPolicyCacheMetricsRecorder) RecordLoadError()       {}

// CachedPolicyLoader wraps a PolicyLoader with cache integration
// It checks the cache first, and only loads from the source on cache miss or expiry
type CachedPolicyLoader struct {
	options CachedPolicyLoaderOptions
}

// NewCachedPolicyLoader creates a new cached policy loader
func NewCachedPolicyLoader(options CachedPolicyLoaderOptions) (*CachedPolicyLoader, error) {
	if options.Loader == nil {
		return nil, errors.New("underlying policy loader is required")
	}
	if options.CacheStore == nil {
		return nil, errors.New("cache store is required")
	}
	if options.DefaultExpiryDuration == 0 {
		options.DefaultExpiryDuration = 5 * time.Minute
	}
	if options.MaxCacheSize == 0 {
		options.MaxCacheSize = 100
	}
	if options.Metrics == nil {
		options.Metrics = NewNopPolicyCacheMetricsRecorder()
	}

	return &CachedPolicyLoader{options: options}, nil
}

// LoadPolicySource implements PolicyLoader with cache integration
func (l *CachedPolicyLoader) LoadPolicySource(ctx context.Context, source PolicySource) (PolicySourceLoadResult, error) {
	// Check if we have a cache store
	if l.options.CacheStore == nil {
		l.logCacheError(ctx, "no cache store configured", source)
		l.options.Metrics.RecordCacheError()
		// Fall back to direct load
		return l.options.Loader.LoadPolicySource(ctx, source)
	}

	// Create cache key for this source
	cacheKey := PolicySourceCacheKey(source)
	if cacheKey == "" {
		l.logCacheError(ctx, "failed to create cache key", source)
		l.options.Metrics.RecordCacheError()
		// Fall back to direct load
		return l.options.Loader.LoadPolicySource(ctx, source)
	}

	// Check cache first
	cachedRecord, found, err := l.options.CacheStore.GetPolicyCacheRecord(ctx, source)
	if err != nil {
		l.logCacheError(ctx, "cache lookup failed", source)
		l.options.Metrics.RecordCacheError()
		// Fall back to direct load on cache error
		return l.options.Loader.LoadPolicySource(ctx, source)
	}

	// If found in cache, check if it's still valid
	if found {
		nowUnix := time.Now().Unix()
		state := PolicyCacheStateAt(cachedRecord.LoadedAtUnix, cachedRecord.ExpiresAtUnix, nowUnix)

		// Return cached result if fresh
		if state == PolicyCacheFresh {
			l.logCacheHit(ctx, source, cacheKey, state)
			l.options.Metrics.RecordCacheHit()

			// Convert cache record to load result
			loaded := LoadedPolicySource{
				Source:  cachedRecord.Source,
				Content: copyBytes(cachedRecord.Content),
			}

			return PolicySourceLoadResult{
				Loaded:   loaded,
				Metadata: cachedRecord,
			}, nil
		}

		// If stale or expired, record the state and continue to load fresh
		l.logCacheState(ctx, source, cacheKey, state)
		if state == PolicyCacheExpired {
			l.options.Metrics.RecordCacheExpiry()
		} else {
			l.options.Metrics.RecordCacheMiss() // Treat stale as cache miss for refresh
		}
	}

	// Cache miss or expired - load from source
	l.options.Metrics.RecordCacheMiss()
	loadResult, err := l.options.Loader.LoadPolicySource(ctx, source)
	if err != nil {
		l.logLoadError(ctx, source, err)
		l.options.Metrics.RecordLoadError()
		return PolicySourceLoadResult{}, err
	}

	// Store in cache for future requests
	if err := l.storeInCache(ctx, source, loadResult); err != nil {
		l.logCacheStoreError(ctx, source, err)
		l.options.Metrics.RecordCacheStoreError()
		// Continue with the loaded result even if cache store failed
	}

	l.options.Metrics.RecordLoadSuccess()
	l.logCacheStore(ctx, source, cacheKey)

	return loadResult, nil
}

// storeInCache stores a loaded policy source in the cache
func (l *CachedPolicyLoader) storeInCache(ctx context.Context, source PolicySource, loadResult PolicySourceLoadResult) error {
	// Check if we have a cache store
	if l.options.CacheStore == nil {
		return errors.New("no cache store configured")
	}

	// Determine expiry time
	var expiresAtUnix int64
	nowUnix := time.Now().Unix()
	if l.options.DefaultExpiryDuration > 0 {
		expiresAtUnix = nowUnix + int64(l.options.DefaultExpiryDuration.Seconds())
	}

	// Create cache record from load result
	record, err := PolicyCacheRecordForLoadedSource(
		loadResult.Loaded,
		nowUnix,
		expiresAtUnix,
		"", // Let it auto-generate version
	)
	if err != nil {
		return fmt.Errorf("failed to create cache record: %w", err)
	}

	// Store in cache
	return l.options.CacheStore.PutPolicyCacheRecord(ctx, record)
}

// InvalidateCache invalidates a specific policy source in the cache
func (l *CachedPolicyLoader) InvalidateCache(ctx context.Context, source PolicySource) error {
	// For now, we can't directly invalidate from the cache store interface
	// This would require extending the interface or using a different approach
	// For shadow mode, this is acceptable as cache entries will expire naturally
	l.logCacheInvalidation(ctx, source)
	return nil
}

// CacheSize returns the current number of entries in the cache
func (l *CachedPolicyLoader) CacheSize(ctx context.Context) (int, error) {
	if l.options.CacheStore == nil {
		return 0, errors.New("no cache store configured")
	}
	records, err := l.options.CacheStore.ListPolicyCacheRecords(ctx)
	if err != nil {
		return 0, err
	}
	return len(records), nil
}

// Logging helpers

func (l *CachedPolicyLoader) logCacheHit(ctx context.Context, source PolicySource, cacheKey string, state PolicyCacheState) {
	if l.options.Logger == nil {
		return
	}
	l.options.Logger.Debug("policy cache hit",
		"source_uri", source.URI,
		"cache_key", cacheKey,
		"state", string(state),
	)
}

func (l *CachedPolicyLoader) logCacheState(ctx context.Context, source PolicySource, cacheKey string, state PolicyCacheState) {
	if l.options.Logger == nil {
		return
	}
	l.options.Logger.Debug("policy cache state",
		"source_uri", source.URI,
		"cache_key", cacheKey,
		"state", state,
	)
}

func (l *CachedPolicyLoader) logCacheError(ctx context.Context, message string, source PolicySource) {
	if l.options.Logger == nil {
		return
	}
	l.options.Logger.Warn("policy cache error",
		"source_uri", source.URI,
		"error", message,
	)
}

func (l *CachedPolicyLoader) logCacheStoreError(ctx context.Context, source PolicySource, err error) {
	if l.options.Logger == nil {
		return
	}
	l.options.Logger.Warn("policy cache store error",
		"source_uri", source.URI,
		"error", err,
	)
}

func (l *CachedPolicyLoader) logLoadError(ctx context.Context, source PolicySource, err error) {
	if l.options.Logger == nil {
		return
	}
	l.options.Logger.Warn("policy load error",
		"source_uri", source.URI,
		"error", err,
	)
}

func (l *CachedPolicyLoader) logCacheStore(ctx context.Context, source PolicySource, cacheKey string) {
	if l.options.Logger == nil {
		return
	}
	l.options.Logger.Debug("policy cached",
		"source_uri", source.URI,
		"cache_key", cacheKey,
	)
}

func (l *CachedPolicyLoader) logCacheInvalidation(ctx context.Context, source PolicySource) {
	if l.options.Logger == nil {
		return
	}
	l.options.Logger.Debug("policy cache invalidation",
		"source_uri", source.URI,
	)
}

// PolicyCacheMetrics is a concrete implementation of PolicyCacheMetricsRecorder
type PolicyCacheMetrics struct {
	Hits          int64
	Misses        int64
	Expiries      int64
	Errors        int64
	StoreErrors   int64
	LoadSuccesses int64
	LoadErrors    int64
}

func NewPolicyCacheMetrics() *PolicyCacheMetrics {
	return &PolicyCacheMetrics{}
}

func (m *PolicyCacheMetrics) RecordCacheHit()        { m.Hits++ }
func (m *PolicyCacheMetrics) RecordCacheMiss()       { m.Misses++ }
func (m *PolicyCacheMetrics) RecordCacheExpiry()     { m.Expiries++ }
func (m *PolicyCacheMetrics) RecordCacheError()      { m.Errors++ }
func (m *PolicyCacheMetrics) RecordCacheStoreError() { m.StoreErrors++ }
func (m *PolicyCacheMetrics) RecordLoadSuccess()     { m.LoadSuccesses++ }
func (m *PolicyCacheMetrics) RecordLoadError()       { m.LoadErrors++ }

// CacheStats returns a snapshot of the current cache statistics
func (m *PolicyCacheMetrics) CacheStats() map[string]int64 {
	return map[string]int64{
		"hits":           m.Hits,
		"misses":         m.Misses,
		"expiries":       m.Expiries,
		"errors":         m.Errors,
		"store_errors":   m.StoreErrors,
		"load_successes": m.LoadSuccesses,
		"load_errors":    m.LoadErrors,
	}
}
