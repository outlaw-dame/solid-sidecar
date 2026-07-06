// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockEvaluator is a simple mock evaluator for testing
type mockEvaluator struct {
	mu          sync.Mutex
	callCount   int
	returnValue Decision
	returnError error
}

func (m *mockEvaluator) Evaluate(ctx context.Context, request Request) (Decision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	return m.returnValue, m.returnError
}

// mockPolicyChangeNotifier is a mock implementation for testing
type mockPolicyChangeNotifier struct {
	events []PolicyChangeEvent
	mu     sync.Mutex
}

func (m *mockPolicyChangeNotifier) SubscribePolicyChanges() <-chan PolicyChangeEvent {
	ch := make(chan PolicyChangeEvent, 100)
	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, event := range m.events {
			ch <- event
		}
	}()
	return ch
}

func (m *mockPolicyChangeNotifier) Close() error {
	return nil
}

func (m *mockPolicyChangeNotifier) AddEvent(event PolicyChangeEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

// TestCachingEvaluatorCreation tests creating a caching evaluator
func TestCachingEvaluatorCreation(t *testing.T) {
	t.Parallel()

	// Create mock evaluator
	mockEval := &mockEvaluator{
		returnValue: Decision{
			SchemaVersion: SchemaVersion,
			RequestID:     "test-request",
			Decision:      DecisionAllow,
			ReasonCode:    ReasonPolicyAllow,
		},
	}

	// Create caching evaluator with default options
	options := DefaultCachingEvaluatorOptions()
	cachingEval, err := NewCachingEvaluator(mockEval, options, nil)
	if err != nil {
		t.Fatalf("Failed to create caching evaluator: %v", err)
	}

	// Verify it's enabled by default
	if !cachingEval.IsCachingEnabled() {
		t.Error("Caching should be enabled by default")
	}

	// Verify it implements the Evaluator interface
	var _ Evaluator = cachingEval
}

// TestCachingEvaluatorWithNilEvaluator tests error handling with nil evaluator
func TestCachingEvaluatorWithNilEvaluator(t *testing.T) {
	t.Parallel()

	// Try to create with nil evaluator
	_, err := NewCachingEvaluator(nil, DefaultCachingEvaluatorOptions(), nil)
	if err == nil {
		t.Error("Expected error when evaluator is nil")
	}
	if !errors.Is(err, ErrCachingEvaluatorNotConfigured) {
		t.Errorf("Expected ErrCachingEvaluatorNotConfigured, got: %v", err)
	}
}

// TestCachingEvaluatorCachingEnabled tests caching behavior when enabled
func TestCachingEvaluatorCachingEnabled(t *testing.T) {
	t.Parallel()

	// Create mock evaluator that returns allow
	mockEval := &mockEvaluator{
		returnValue: Decision{
			SchemaVersion:   SchemaVersion,
			RequestID:       "test-request",
			Decision:        DecisionAllow,
			ReasonCode:      ReasonPolicyAllow,
			CacheTTLSeconds: 60,
			PolicyVersion:   "v1",
		},
	}

	// Create caching evaluator
	options := DefaultCachingEvaluatorOptions()
	cachingEval, err := NewCachingEvaluator(mockEval, options, nil)
	if err != nil {
		t.Fatalf("Failed to create caching evaluator: %v", err)
	}

	ctx := context.Background()

	// Create a test request
	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-1",
		Method:         "GET",
		ResourceURI:    "https://example.com/resource",
		AgentWebID:     "https://example.com/webid#me",
		ClientID:       "test-client",
		Issuer:         "https://example.com/issuer",
		RequestedModes: []AccessMode{AccessModeRead},
		PolicyVersion:  "v1",
		NowUnix:        time.Now().Unix(),
	}

	// First call - should evaluate and cache
	decision1, err := cachingEval.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("First evaluation failed: %v", err)
	}
	if decision1.Decision != DecisionAllow {
		t.Errorf("Expected allow decision, got: %s", decision1.Decision)
	}
	if mockEval.callCount != 1 {
		t.Errorf("Expected 1 evaluator call, got: %d", mockEval.callCount)
	}

	// Second call with same request - should use cache
	decision2, err := cachingEval.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("Second evaluation failed: %v", err)
	}
	if decision2.Decision != DecisionAllow {
		t.Errorf("Expected allow decision from cache, got: %s", decision2.Decision)
	}
	if decision2.ReasonCode != ReasonCachedDecision {
		t.Errorf("Expected cached decision reason, got: %s", decision2.ReasonCode)
	}
	if mockEval.callCount != 1 {
		t.Errorf("Expected still 1 evaluator call (cached), got: %d", mockEval.callCount)
	}

	// Check cache metrics
	metrics := cachingEval.GetCacheMetrics()
	if metrics.Hits < 1 {
		t.Errorf("Expected at least 1 cache hit, got: %d", metrics.Hits)
	}
	if metrics.Puts < 1 {
		t.Errorf("Expected at least 1 cache put, got: %d", metrics.Puts)
	}
}

// TestCachingEvaluatorCachingDisabled tests behavior when caching is disabled
func TestCachingEvaluatorCachingDisabled(t *testing.T) {
	t.Parallel()

	// Create mock evaluator
	mockEval := &mockEvaluator{
		returnValue: Decision{
			SchemaVersion: SchemaVersion,
			RequestID:     "test-request",
			Decision:      DecisionAllow,
			ReasonCode:    ReasonPolicyAllow,
		},
	}

	// Create caching evaluator with caching disabled
	options := DefaultCachingEvaluatorOptions()
	options.EnableCaching = false
	cachingEval, err := NewCachingEvaluator(mockEval, options, nil)
	if err != nil {
		t.Fatalf("Failed to create caching evaluator: %v", err)
	}

	if cachingEval.IsCachingEnabled() {
		t.Error("Caching should be disabled")
	}

	ctx := context.Background()
	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-1",
		Method:         "GET",
		ResourceURI:    "https://example.com/resource",
		AgentWebID:     "https://example.com/webid#me",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        time.Now().Unix(),
	}

	// First call - should evaluate
	_, err = cachingEval.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("First evaluation failed: %v", err)
	}
	if mockEval.callCount != 1 {
		t.Errorf("Expected 1 evaluator call, got: %d", mockEval.callCount)
	}

	// Second call - should evaluate again (caching disabled)
	_, err = cachingEval.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("Second evaluation failed: %v", err)
	}
	if mockEval.callCount != 2 {
		t.Errorf("Expected 2 evaluator calls (no caching), got: %d", mockEval.callCount)
	}

	// Check cache metrics - should have no activity
	metrics := cachingEval.GetCacheMetrics()
	if metrics.Hits != 0 {
		t.Errorf("Expected 0 cache hits when caching disabled, got: %d", metrics.Hits)
	}
}

// TestCachingEvaluatorInvalidation tests cache invalidation
func TestCachingEvaluatorInvalidation(t *testing.T) {
	t.Parallel()

	// Create mock evaluator
	mockEval := &mockEvaluator{
		returnValue: Decision{
			SchemaVersion:   SchemaVersion,
			RequestID:       "test-request",
			Decision:        DecisionAllow,
			ReasonCode:      ReasonPolicyAllow,
			CacheTTLSeconds: 60,
			PolicyVersion:   "v1",
		},
	}

	// Create caching evaluator
	options := DefaultCachingEvaluatorOptions()
	cachingEval, err := NewCachingEvaluator(mockEval, options, nil)
	if err != nil {
		t.Fatalf("Failed to create caching evaluator: %v", err)
	}

	ctx := context.Background()

	// Create a test request
	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-1",
		Method:         "GET",
		ResourceURI:    "https://example.com/resource",
		AgentWebID:     "https://example.com/webid#me",
		RequestedModes: []AccessMode{AccessModeRead},
		PolicyVersion:  "v1",
		NowUnix:        time.Now().Unix(),
	}

	// Evaluate and cache
	_, err = cachingEval.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}
	if mockEval.callCount != 1 {
		t.Errorf("Expected 1 evaluator call, got: %d", mockEval.callCount)
	}

	// Clear cache
	err = cachingEval.ClearCache(ctx)
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	// Evaluate again - should call evaluator again
	_, err = cachingEval.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("Evaluation after clear failed: %v", err)
	}
	if mockEval.callCount != 2 {
		t.Errorf("Expected 2 evaluator calls after cache clear, got: %d", mockEval.callCount)
	}
}

// TestCachingEvaluatorPolicyInvalidation tests policy-specific invalidation
func TestCachingEvaluatorPolicyInvalidation(t *testing.T) {
	t.Parallel()

	// Create mock evaluator
	mockEval := &mockEvaluator{
		returnValue: Decision{
			SchemaVersion:   SchemaVersion,
			RequestID:       "test-request",
			Decision:        DecisionAllow,
			ReasonCode:      ReasonPolicyAllow,
			CacheTTLSeconds: 60,
			PolicyVersion:   "v1",
		},
	}

	// Create caching evaluator
	options := DefaultCachingEvaluatorOptions()
	cachingEval, err := NewCachingEvaluator(mockEval, options, nil)
	if err != nil {
		t.Fatalf("Failed to create caching evaluator: %v", err)
	}

	ctx := context.Background()

	// Create requests with different policy versions
	request1 := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-1",
		Method:         "GET",
		ResourceURI:    "https://example.com/resource",
		AgentWebID:     "https://example.com/webid#me",
		RequestedModes: []AccessMode{AccessModeRead},
		PolicyVersion:  "v1",
		NowUnix:        time.Now().Unix(),
	}

	request2 := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-2",
		Method:         "GET",
		ResourceURI:    "https://example.com/resource2",
		AgentWebID:     "https://example.com/webid#me",
		RequestedModes: []AccessMode{AccessModeRead},
		PolicyVersion:  "v2",
		NowUnix:        time.Now().Unix(),
	}

	// Evaluate both requests
	_, err = cachingEval.Evaluate(ctx, request1)
	if err != nil {
		t.Fatalf("Evaluation 1 failed: %v", err)
	}
	_, err = cachingEval.Evaluate(ctx, request2)
	if err != nil {
		t.Fatalf("Evaluation 2 failed: %v", err)
	}
	if mockEval.callCount != 2 {
		t.Errorf("Expected 2 evaluator calls, got: %d", mockEval.callCount)
	}

	// Invalidate policy v1
	err = cachingEval.InvalidatePolicy(ctx, "v1")
	if err != nil {
		t.Fatalf("Failed to invalidate policy: %v", err)
	}

	// Evaluate request1 again - should call evaluator again
	_, err = cachingEval.Evaluate(ctx, request1)
	if err != nil {
		t.Fatalf("Evaluation after invalidation failed: %v", err)
	}
	// Should have called evaluator again for request1
	if mockEval.callCount != 3 {
		t.Errorf("Expected 3 evaluator calls after policy invalidation, got: %d", mockEval.callCount)
	}

	// Evaluate request2 - should still use cache (v2 not invalidated)
	_, err = cachingEval.Evaluate(ctx, request2)
	if err != nil {
		t.Fatalf("Evaluation of request2 after invalidation failed: %v", err)
	}
	// Should still be 3 (cached)
	if mockEval.callCount != 3 {
		t.Errorf("Expected still 3 evaluator calls (request2 cached), got: %d", mockEval.callCount)
	}
}

// TestCachingEvaluatorEnableDisable tests toggling caching on/off
func TestCachingEvaluatorEnableDisable(t *testing.T) {
	t.Parallel()

	// Create mock evaluator
	mockEval := &mockEvaluator{
		returnValue: Decision{
			SchemaVersion: SchemaVersion,
			RequestID:     "test-request",
			Decision:      DecisionAllow,
			ReasonCode:    ReasonPolicyAllow,
		},
	}

	// Create caching evaluator
	options := DefaultCachingEvaluatorOptions()
	cachingEval, err := NewCachingEvaluator(mockEval, options, nil)
	if err != nil {
		t.Fatalf("Failed to create caching evaluator: %v", err)
	}

	ctx := context.Background()
	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-1",
		Method:         "GET",
		ResourceURI:    "https://example.com/resource",
		AgentWebID:     "https://example.com/webid#me",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        time.Now().Unix(),
	}

	// Initially caching is enabled
	if !cachingEval.IsCachingEnabled() {
		t.Error("Caching should be enabled initially")
	}

	// First call
	_, err = cachingEval.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("First evaluation failed: %v", err)
	}
	if mockEval.callCount != 1 {
		t.Errorf("Expected 1 evaluator call, got: %d", mockEval.callCount)
	}

	// Disable caching
	cachingEval.EnableCaching(false)
	if cachingEval.IsCachingEnabled() {
		t.Error("Caching should be disabled after EnableCaching(false)")
	}

	// Second call - should not use cache
	_, err = cachingEval.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("Second evaluation failed: %v", err)
	}
	if mockEval.callCount != 2 {
		t.Errorf("Expected 2 evaluator calls (no caching), got: %d", mockEval.callCount)
	}

	// Re-enable caching
	cachingEval.EnableCaching(true)
	if !cachingEval.IsCachingEnabled() {
		t.Error("Caching should be enabled after EnableCaching(true)")
	}

	// Third call - should use cache again
	_, err = cachingEval.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("Third evaluation failed: %v", err)
	}
	// Should still be 2 (cached)
	if mockEval.callCount != 2 {
		t.Errorf("Expected still 2 evaluator calls (cached), got: %d", mockEval.callCount)
	}
}

// TestCachingEvaluatorResourceInvalidation tests resource-specific invalidation
func TestCachingEvaluatorResourceInvalidation(t *testing.T) {
	t.Parallel()

	// Create mock evaluator
	mockEval := &mockEvaluator{
		returnValue: Decision{
			SchemaVersion:   SchemaVersion,
			RequestID:       "test-request",
			Decision:        DecisionAllow,
			ReasonCode:      ReasonPolicyAllow,
			CacheTTLSeconds: 60,
		},
	}

	// Create caching evaluator
	options := DefaultCachingEvaluatorOptions()
	cachingEval, err := NewCachingEvaluator(mockEval, options, nil)
	if err != nil {
		t.Fatalf("Failed to create caching evaluator: %v", err)
	}

	ctx := context.Background()

	// Create requests for different resources
	request1 := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-1",
		Method:         "GET",
		ResourceURI:    "https://example.com/resource1",
		AgentWebID:     "https://example.com/webid#me",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        time.Now().Unix(),
	}

	request2 := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-2",
		Method:         "GET",
		ResourceURI:    "https://example.com/resource2",
		AgentWebID:     "https://example.com/webid#me",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        time.Now().Unix(),
	}

	// Evaluate both requests
	_, err = cachingEval.Evaluate(ctx, request1)
	if err != nil {
		t.Fatalf("Evaluation 1 failed: %v", err)
	}
	_, err = cachingEval.Evaluate(ctx, request2)
	if err != nil {
		t.Fatalf("Evaluation 2 failed: %v", err)
	}
	if mockEval.callCount != 2 {
		t.Errorf("Expected 2 evaluator calls, got: %d", mockEval.callCount)
	}

	// Invalidate resource1
	err = cachingEval.InvalidateResource(ctx, "https://example.com/resource1")
	if err != nil {
		t.Fatalf("Failed to invalidate resource: %v", err)
	}

	// Evaluate request1 again - should call evaluator again
	_, err = cachingEval.Evaluate(ctx, request1)
	if err != nil {
		t.Fatalf("Evaluation after invalidation failed: %v", err)
	}
	if mockEval.callCount != 3 {
		t.Errorf("Expected 3 evaluator calls after resource invalidation, got: %d", mockEval.callCount)
	}

	// Evaluate request2 - should still use cache (resource2 not invalidated)
	_, err = cachingEval.Evaluate(ctx, request2)
	if err != nil {
		t.Fatalf("Evaluation of request2 after invalidation failed: %v", err)
	}
	// Should still be 3 (cached)
	if mockEval.callCount != 3 {
		t.Errorf("Expected still 3 evaluator calls (request2 cached), got: %d", mockEval.callCount)
	}
}

// TestCachingEvaluatorErrorHandling tests error handling
func TestCachingEvaluatorErrorHandling(t *testing.T) {
	t.Parallel()

	// Create mock evaluator that returns an error
	expectedErr := errors.New("evaluation error")
	mockEval := &mockEvaluator{
		returnError: expectedErr,
	}

	// Create caching evaluator
	options := DefaultCachingEvaluatorOptions()
	cachingEval, err := NewCachingEvaluator(mockEval, options, nil)
	if err != nil {
		t.Fatalf("Failed to create caching evaluator: %v", err)
	}

	ctx := context.Background()
	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-1",
		Method:         "GET",
		ResourceURI:    "https://example.com/resource",
		AgentWebID:     "https://example.com/webid#me",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        time.Now().Unix(),
	}

	// Evaluation should fail
	_, err = cachingEval.Evaluate(ctx, request)
	if err == nil {
		t.Error("Expected error from evaluator")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected wrapped error, got: %v", err)
	}
}
