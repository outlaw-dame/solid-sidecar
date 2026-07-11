// Package storage provides the production storage engine for the Solid runtime.
// This file tests the cache invalidation functionality.
package storage

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// mockCacheInvalidator is a mock implementation for testing
type mockCacheInvalidator struct {
	onInvalidationCalled bool
	lastEvent            CacheInvalidationEvent
	errors               []error
	invalidations        int
}

func (m *mockCacheInvalidator) OnCacheInvalidation(ctx context.Context, event CacheInvalidationEvent) error {
	m.onInvalidationCalled = true
	m.lastEvent = event
	m.invalidations++
	if len(m.errors) > 0 {
		err := m.errors[0]
		m.errors = m.errors[1:]
		return err
	}
	return nil
}

func TestCacheInvalidationEvent(t *testing.T) {
	// Test event creation
	event := CacheInvalidationEvent{
		ResourceURI: "https://example.com/resource",
		IsPolicy:    true,
		PolicyURI:   "https://example.com/resource",
		Action:      "put",
		Timestamp:   time.Now().UTC(),
	}

	if event.ResourceURI != "https://example.com/resource" {
		t.Errorf("Expected ResourceURI to be 'https://example.com/resource', got '%s'", event.ResourceURI)
	}

	if !event.IsPolicy {
		t.Error("Expected IsPolicy to be true")
	}

	if event.Action != "put" {
		t.Errorf("Expected Action to be 'put', got '%s'", event.Action)
	}

	if event.Timestamp.IsZero() {
		t.Error("Expected Timestamp to be set")
	}
}

func TestAuthzCacheInvalidator(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Track invalidation calls
	policyInvalidations := 0
	decisionInvalidations := 0

	invalidator := NewAuthzCacheInvalidator(
		func(ctx context.Context, policyURI string) error {
			policyInvalidations++
			return nil
		},
		func(ctx context.Context, resourceURI string, isPolicy bool) error {
			decisionInvalidations++
			return nil
		},
		logger,
	)

	// Test policy resource invalidation
	event := CacheInvalidationEvent{
		ResourceURI: "https://example.com/policy.acl",
		IsPolicy:    true,
		PolicyURI:   "https://example.com/policy.acl",
		Action:      "put",
		Timestamp:   time.Now().UTC(),
	}

	err := invalidator.OnCacheInvalidation(ctx, event)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if policyInvalidations != 1 {
		t.Errorf("Expected 1 policy invalidation, got %d", policyInvalidations)
	}

	if decisionInvalidations != 2 {
		t.Errorf("Expected 2 decision invalidations (resource + policy), got %d", decisionInvalidations)
	}

	// Reset counters
	policyInvalidations = 0
	decisionInvalidations = 0

	// Test non-policy resource invalidation
	event2 := CacheInvalidationEvent{
		ResourceURI: "https://example.com/data",
		IsPolicy:    false,
		PolicyURI:   "",
		Action:      "delete",
		Timestamp:   time.Now().UTC(),
	}

	err = invalidator.OnCacheInvalidation(ctx, event2)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if policyInvalidations != 0 {
		t.Errorf("Expected 0 policy invalidations for non-policy resource, got %d", policyInvalidations)
	}

	if decisionInvalidations != 1 {
		t.Errorf("Expected 1 decision invalidation for non-policy resource, got %d", decisionInvalidations)
	}

	// Test error handling - policy invalidation error
	policyInvalidations = 0
	decisionInvalidations = 0

	invalidatorWithError := NewAuthzCacheInvalidator(
		func(ctx context.Context, policyURI string) error {
			policyInvalidations++
			return errors.New("policy cache error")
		},
		func(ctx context.Context, resourceURI string, isPolicy bool) error {
			decisionInvalidations++
			return nil
		},
		logger,
	)

	err = invalidatorWithError.OnCacheInvalidation(ctx, event)
	if err != nil {
		t.Errorf("Expected no error from OnCacheInvalidation even if policy cache fails, got: %v", err)
	}

	if policyInvalidations != 1 {
		t.Errorf("Expected 1 policy invalidation attempt, got %d", policyInvalidations)
	}

	// Decision cache should still be invalidated even if policy cache fails
	if decisionInvalidations != 2 {
		t.Errorf("Expected 2 decision invalidations, got %d", decisionInvalidations)
	}

	// Test metrics
	metrics := invalidator.GetMetrics()
	if metrics.InvalidationEvents == 0 {
		t.Error("Expected InvalidationEvents to be > 0")
	}
}

func TestNoOpCacheInvalidator(t *testing.T) {
	ctx := context.Background()
	invalidator := NewNoOpCacheInvalidator()

	event := CacheInvalidationEvent{
		ResourceURI: "https://example.com/resource",
		IsPolicy:    true,
		Action:      "put",
		Timestamp:   time.Now().UTC(),
	}

	err := invalidator.OnCacheInvalidation(ctx, event)
	if err != nil {
		t.Errorf("Unexpected error from NoOpCacheInvalidator: %v", err)
	}
}

func TestCacheInvalidatorMetrics(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	invalidator := NewAuthzCacheInvalidator(
		func(ctx context.Context, policyURI string) error { return nil },
		func(ctx context.Context, resourceURI string, isPolicy bool) error { return nil },
		logger,
	)

	// Initial metrics should be zero
	metrics := invalidator.GetMetrics()
	if metrics.InvalidationEvents != 0 {
		t.Errorf("Expected 0 initial InvalidationEvents, got %d", metrics.InvalidationEvents)
	}

	// After invalidation
	event := CacheInvalidationEvent{
		ResourceURI: "https://example.com/resource",
		IsPolicy:    true,
		PolicyURI:   "https://example.com/resource",
		Action:      "put",
		Timestamp:   time.Now().UTC(),
	}

	_ = invalidator.OnCacheInvalidation(ctx, event)

	metrics = invalidator.GetMetrics()
	if metrics.InvalidationEvents != 1 {
		t.Errorf("Expected 1 InvalidationEvents, got %d", metrics.InvalidationEvents)
	}

	if metrics.PolicyInvalidations != 1 {
		t.Errorf("Expected 1 PolicyInvalidations, got %d", metrics.PolicyInvalidations)
	}

	if metrics.ResourceInvalidations != 2 {
		t.Errorf("Expected 2 ResourceInvalidations, got %d", metrics.ResourceInvalidations)
	}

	if metrics.LastInvalidation.IsZero() {
		t.Error("Expected LastInvalidation to be set")
	}
}
