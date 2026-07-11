// Package storage provides the production storage engine for the Solid runtime.
// This file implements the cache invalidator for authorization caches.
package storage

import (
	"context"
	"log/slog"
	"time"
)

// AuthzCacheInvalidator implements CacheInvalidator for authorization caches.
// It invalidates decision and policy caches when resources change.
type AuthzCacheInvalidator struct {
	// policyCacheInvalidator is a function that invalidates the policy cache
	// This is typically a method from the policy engine
	policyCacheInvalidator func(ctx context.Context, policyURI string) error

	// decisionCacheInvalidator is a function that invalidates the decision cache
	// This is typically a method from the authz cache
	decisionCacheInvalidator func(ctx context.Context, resourceURI string, isPolicy bool) error

	// logger is used for logging
	logger *slog.Logger

	// metrics for tracking invalidation events
	metrics *CacheInvalidatorMetrics
}

// CacheInvalidatorMetrics tracks cache invalidation statistics
type CacheInvalidatorMetrics struct {
	InvalidationEvents    int64
	PolicyInvalidations   int64
	ResourceInvalidations int64
	Errors                int64
	LastInvalidation      time.Time
}

// NewAuthzCacheInvalidator creates a new AuthzCacheInvalidator
func NewAuthzCacheInvalidator(
	policyInvalidator func(ctx context.Context, policyURI string) error,
	decisionInvalidator func(ctx context.Context, resourceURI string, isPolicy bool) error,
	logger *slog.Logger,
) *AuthzCacheInvalidator {
	return &AuthzCacheInvalidator{
		policyCacheInvalidator:   policyInvalidator,
		decisionCacheInvalidator: decisionInvalidator,
		logger:                   logger.With("component", "authz_cache_invalidator"),
		metrics:                  &CacheInvalidatorMetrics{},
	}
}

// OnCacheInvalidation implements CacheInvalidator.OnCacheInvalidation
func (a *AuthzCacheInvalidator) OnCacheInvalidation(ctx context.Context, event CacheInvalidationEvent) error {
	a.metrics.InvalidationEvents++
	a.metrics.LastInvalidation = time.Now()

	// Log the invalidation event
	a.logger.Debug("Cache invalidation triggered",
		"resource_uri", event.ResourceURI,
		"is_policy", event.IsPolicy,
		"policy_uri", event.PolicyURI,
		"action", event.Action,
	)

	// Invalidate policy cache if this is a policy resource
	if event.IsPolicy && event.PolicyURI != "" && a.policyCacheInvalidator != nil {
		if err := a.policyCacheInvalidator(ctx, event.PolicyURI); err != nil {
			a.logger.Warn("Policy cache invalidation failed",
				"policy_uri", event.PolicyURI,
				"error", err,
			)
			a.metrics.Errors++
			// Don't return error, continue with decision cache invalidation
		} else {
			a.metrics.PolicyInvalidations++
		}
	}

	// Invalidate decision cache for the resource
	if a.decisionCacheInvalidator != nil {
		// Also invalidate for related resources if this is a policy
		resourcesToInvalidate := []string{event.ResourceURI}

		// If this is a policy, also invalidate decisions that depend on this policy
		// This includes resources that might reference this policy
		if event.IsPolicy {
			// For now, we just invalidate the policy itself
			// In a more sophisticated implementation, we would track which resources
			// reference which policies and invalidate those as well
			resourcesToInvalidate = append(resourcesToInvalidate, event.PolicyURI)
		}

		for _, resourceURI := range resourcesToInvalidate {
			if err := a.decisionCacheInvalidator(ctx, resourceURI, event.IsPolicy); err != nil {
				a.logger.Warn("Decision cache invalidation failed",
					"resource_uri", resourceURI,
					"error", err,
				)
				a.metrics.Errors++
				// Don't return error, continue with other resources
			} else {
				a.metrics.ResourceInvalidations++
			}
		}
	}

	return nil
}

// GetMetrics returns the current metrics
func (a *AuthzCacheInvalidator) GetMetrics() CacheInvalidatorMetrics {
	a.metrics.LastInvalidation = time.Now() // Update timestamp
	return *a.metrics
}

// NewNoOpCacheInvalidator creates a no-op cache invalidator for testing
func NewNoOpCacheInvalidator() *AuthzCacheInvalidator {
	return &AuthzCacheInvalidator{
		policyCacheInvalidator:   func(ctx context.Context, policyURI string) error { return nil },
		decisionCacheInvalidator: func(ctx context.Context, resourceURI string, isPolicy bool) error { return nil },
		logger:                   slog.Default(),
		metrics:                  &CacheInvalidatorMetrics{},
	}
}
