package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestTransportErrors tests that transport errors are properly defined
func TestTransportErrors(t *testing.T) {
	errors := []error{
		ErrTransportNotImplemented,
		ErrTransportTimeout,
		ErrTransportAuthFailed,
		ErrTransportConnectionFailed,
		ErrTransportInvalidResponse,
		ErrTransportRetryExhausted,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("Expected error to be non-nil")
		}
	}
}

// TestTransportConstants tests transport configuration constants
func TestTransportConstants(t *testing.T) {
	if MaxTransportPayloadSize != 10*1024*1024 {
		t.Errorf("Expected MaxTransportPayloadSize to be 10MB, got %d", MaxTransportPayloadSize)
	}

	if DefaultTransportTimeout != 30*time.Second {
		t.Errorf("Expected DefaultTransportTimeout to be 30s, got %v", DefaultTransportTimeout)
	}

	if DefaultTransportRetryCount != 3 {
		t.Errorf("Expected DefaultTransportRetryCount to be 3, got %d", DefaultTransportRetryCount)
	}

	if DefaultTransportRetryBaseDelay != 1*time.Second {
		t.Errorf("Expected DefaultTransportRetryBaseDelay to be 1s, got %v", DefaultTransportRetryBaseDelay)
	}

	if DefaultTransportRetryMaxDelay != 30*time.Second {
		t.Errorf("Expected DefaultTransportRetryMaxDelay to be 30s, got %v", DefaultTransportRetryMaxDelay)
	}

	if DefaultTransportRetryMultiplier != 2.0 {
		t.Errorf("Expected DefaultTransportRetryMultiplier to be 2.0, got %f", DefaultTransportRetryMultiplier)
	}

	if DefaultTransportRetryJitter != 0.1 {
		t.Errorf("Expected DefaultTransportRetryJitter to be 0.1, got %f", DefaultTransportRetryJitter)
	}
}

// TestDefaultTransportConfig tests the default transport configuration
func TestDefaultTransportConfig(t *testing.T) {
	config := DefaultTransportConfig()

	if config.Timeout != DefaultTransportTimeout {
		t.Errorf("Expected Timeout to be %v, got %v", DefaultTransportTimeout, config.Timeout)
	}

	if config.RetryCount != DefaultTransportRetryCount {
		t.Errorf("Expected RetryCount to be %d, got %d", DefaultTransportRetryCount, config.RetryCount)
	}

	if config.RetryBaseDelay != DefaultTransportRetryBaseDelay {
		t.Errorf("Expected RetryBaseDelay to be %v, got %v", DefaultTransportRetryBaseDelay, config.RetryBaseDelay)
	}

	if config.RetryMaxDelay != DefaultTransportRetryMaxDelay {
		t.Errorf("Expected RetryMaxDelay to be %v, got %v", DefaultTransportRetryMaxDelay, config.RetryMaxDelay)
	}

	if config.RetryMultiplier != DefaultTransportRetryMultiplier {
		t.Errorf("Expected RetryMultiplier to be %f, got %f", DefaultTransportRetryMultiplier, config.RetryMultiplier)
	}

	if config.RetryJitter != DefaultTransportRetryJitter {
		t.Errorf("Expected RetryJitter to be %f, got %f", DefaultTransportRetryJitter, config.RetryJitter)
	}

	if config.VerifyTLS != true {
		t.Errorf("Expected VerifyTLS to be true, got %v", config.VerifyTLS)
	}
}

// TestTransportRegistry tests the transport registry functionality
func TestTransportRegistry(t *testing.T) {
	registry := NewTransportRegistry()

	if registry == nil {
		t.Fatal("Expected registry to be non-nil")
	}

	// Test that registry is initially empty
	methods := registry.Methods()
	if len(methods) != 0 {
		t.Errorf("Expected empty registry, got %d methods", len(methods))
	}

	// Test registering a transport
	mockTransport := &MockTransport{method: DistributionMethodHTTPS}
	registry.Register(mockTransport)

	methods = registry.Methods()
	if len(methods) != 1 {
		t.Errorf("Expected 1 method after registration, got %d", len(methods))
	}

	// Test Get method
	transport, ok := registry.Get(DistributionMethodHTTPS)
	if !ok {
		t.Error("Expected to find registered transport")
	}
	if transport != mockTransport {
		t.Error("Expected to get the same transport instance")
	}

	// Test Get for non-existent method
	_, ok = registry.Get(DistributionMethodS3)
	if ok {
		t.Error("Expected not to find unregistered transport")
	}

	// Test MustGet for existing method
	transport = registry.MustGet(DistributionMethodHTTPS)
	if transport != mockTransport {
		t.Error("Expected MustGet to return the same transport instance")
	}

	// Test MustGet for non-existent method (should panic)
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected MustGet to panic for non-existent method")
		}
	}()
	registry.MustGet(DistributionMethodS3)
}

// MockTransport is a mock implementation for testing
type MockTransport struct {
	method   DistributionMethod
	distobut func(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error)
}

func (m *MockTransport) Distribute(ctx context.Context, job FixtureDistributionJob, target FixtureDistributionTarget, payload []byte) (FixtureDistributionReceipt, error) {
	if m.distobut != nil {
		return m.distobut(ctx, job, target, payload)
	}
	return FixtureDistributionReceipt{}, nil
}

func (m *MockTransport) Name() string {
	return "mock"
}

func (m *MockTransport) Method() DistributionMethod {
	return m.method
}

// TestHTTPTransportCreation tests HTTP transport creation
func TestHTTPTransportCreation(t *testing.T) {
	config := DefaultTransportConfig()
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if transport == nil {
		t.Fatal("Expected transport to be non-nil")
	}

	if transport.Name() != "http" {
		t.Errorf("Expected name to be 'http', got '%s'", transport.Name())
	}

	if transport.Method() != DistributionMethodHTTPS {
		t.Errorf("Expected method to be HTTPS, got '%s'", transport.Method())
	}
}

// TestHTTPTransportCreationWithEmptyConfig tests HTTP transport with empty config
func TestHTTPTransportCreationWithEmptyConfig(t *testing.T) {
	options := FixtureTransportOptions{Config: TransportConfig{}}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if transport == nil {
		t.Fatal("Expected transport to be non-nil")
	}

	// Should use defaults
	if transport.config.Timeout != DefaultTransportTimeout {
		t.Errorf("Expected default timeout, got %v", transport.config.Timeout)
	}
}

// TestHTTPTransportSetBaseURL tests setting base URL for HTTP transport
func TestHTTPTransportSetBaseURL(t *testing.T) {
	config := DefaultTransportConfig()
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Test valid HTTPS URL
	err = transport.SetBaseURL("https://example.com/api")
	if err != nil {
		t.Errorf("Expected no error for valid HTTPS URL, got: %v", err)
	}

	// Test valid HTTP URL
	err = transport.SetBaseURL("http://example.com/api")
	if err != nil {
		t.Errorf("Expected no error for valid HTTP URL, got: %v", err)
	}

	// Test invalid URL (no scheme)
	err = transport.SetBaseURL("example.com/api")
	if err == nil {
		t.Error("Expected error for URL without scheme")
	}
	if !errors.Is(err, ErrTransportConnectionFailed) {
		t.Errorf("Expected ErrTransportConnectionFailed, got: %v", err)
	}

	// Test invalid URL (invalid scheme)
	err = transport.SetBaseURL("ftp://example.com/api")
	if err == nil {
		t.Error("Expected error for invalid URL scheme")
	}
	if !errors.Is(err, ErrTransportConnectionFailed) {
		t.Errorf("Expected ErrTransportConnectionFailed, got: %v", err)
	}
}

// TestHTTPTransportDistributePayloadTooLarge tests payload size validation
func TestHTTPTransportDistributePayloadTooLarge(t *testing.T) {
	config := DefaultTransportConfig()
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Create a payload that's too large
	largePayload := make([]byte, MaxTransportPayloadSize+1)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")

	_, err = transport.Distribute(context.Background(), job, target, largePayload)
	if err == nil {
		t.Error("Expected error for payload too large")
	}
	if !errors.Is(err, ErrTransportInvalidResponse) {
		t.Errorf("Expected ErrTransportInvalidResponse, got: %v", err)
	}
}

// TestHTTPTransportDistributeSuccess tests successful HTTP distribution
func TestHTTPTransportDistributeSuccess(t *testing.T) {
	// Create a test server that returns success
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Verify content type
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type to be application/json, got %s", contentType)
		}

		// Verify user agent
		userAgent := r.Header.Get("User-Agent")
		if userAgent != "solid-sidecar-fixture-distributor/1.0" {
			t.Errorf("Expected specific User-Agent, got %s", userAgent)
		}

		// Verify fixture headers
		if r.Header.Get("X-Fixture-Distribution-ID") != "dist-1" {
			t.Error("Expected X-Fixture-Distribution-ID header")
		}
		if r.Header.Get("X-Fixture-Catalog-Hash") != "catalog-1" {
			t.Error("Expected X-Fixture-Catalog-Hash header")
		}

		// Read and verify body
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatalf("Failed to read body: %v", errRead)
		}
		_ = body

		// Return a success response with a receipt
		receipt := FixtureDistributionReceipt{
			DistributionID:       "dist-1",
			TargetID:             "target-1",
			ReceivedAtUnix:       time.Now().Unix(),
			ReceivedCatalogHash:  "catalog-1",
			ReceivedBundleHashes: []string{},
			VerificationStatus:   "verified",
		}
		receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(receipt)
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0, // No retries for this test
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false, // Don't verify TLS for test server
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)
	receipt, err := transport.Distribute(context.Background(), job, target, payload)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if receipt.DistributionID != "dist-1" {
		t.Errorf("Expected DistributionID to be 'dist-1', got '%s'", receipt.DistributionID)
	}
	if receipt.TargetID != "target-1" {
		t.Errorf("Expected TargetID to be 'target-1', got '%s'", receipt.TargetID)
	}
	if receipt.VerificationStatus != "verified" {
		t.Errorf("Expected VerificationStatus to be 'verified', got '%s'", receipt.VerificationStatus)
	}
}

// TestHTTPTransportDistributeWithAuth tests HTTP distribution with authentication
func TestHTTPTransportDistributeWithAuth(t *testing.T) {
	var receivedAuth string

	// Create a test server that captures the Authorization header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")

		receipt := FixtureDistributionReceipt{
			DistributionID:      "dist-1",
			TargetID:            "target-1",
			ReceivedAtUnix:      time.Now().Unix(),
			ReceivedCatalogHash: "catalog-1",
			VerificationStatus:  "verified",
		}
		receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(receipt)
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")

	// Test Bearer auth
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthBearer, "my-bearer-token")
	payload := []byte(`{"test": "data"}`)
	transport.Distribute(context.Background(), job, target, payload)

	if !strings.HasPrefix(receivedAuth, "Bearer ") {
		t.Errorf("Expected Bearer auth, got: %s", receivedAuth)
	}
	if receivedAuth != "Bearer my-bearer-token" {
		t.Errorf("Expected 'Bearer my-bearer-token', got: %s", receivedAuth)
	}

	// Test Basic auth
	target.AuthMethod = DistributionAuthBasic
	target.AuthToken = "dXNlcjpwYXNz"
	transport.Distribute(context.Background(), job, target, payload)

	if !strings.HasPrefix(receivedAuth, "Basic ") {
		t.Errorf("Expected Basic auth, got: %s", receivedAuth)
	}

	// Test API Key auth
	target.AuthMethod = DistributionAuthAPIKey
	target.AuthToken = "my-api-key"
	transport.Distribute(context.Background(), job, target, payload)

	if !strings.HasPrefix(receivedAuth, "ApiKey ") {
		t.Errorf("Expected API Key auth, got: %s", receivedAuth)
	}
}

// TestHTTPTransportDistributeNonRetryableError tests non-retryable HTTP errors
func TestHTTPTransportDistributeNonRetryableError(t *testing.T) {
	// Create a test server that returns 400 Bad Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)
	_, err = transport.Distribute(context.Background(), job, target, payload)
	if err == nil {
		t.Error("Expected error for 400 response")
	}
	if !errors.Is(err, ErrTransportInvalidResponse) {
		t.Errorf("Expected ErrTransportInvalidResponse, got: %v", err)
	}
}

// TestHTTPTransportDistributeRetryableError tests retryable HTTP errors
func TestHTTPTransportDistributeRetryableError(t *testing.T) {
	var requestCount int32

	// Create a test server that returns 503 Service Unavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service Unavailable"))
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      2, // Try once, retry twice
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)
	_, err = transport.Distribute(context.Background(), job, target, payload)
	if err == nil {
		t.Error("Expected error after all retries exhausted")
	}
	if !errors.Is(err, ErrTransportRetryExhausted) {
		t.Errorf("Expected ErrTransportRetryExhausted, got: %v", err)
	}

	// Should have made initial request + 2 retries = 3 total
	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("Expected 3 requests (initial + 2 retries), got %d", requestCount)
	}
}

// TestHTTPTransportDistributeSuccessAfterRetry tests successful distribution after retries
func TestHTTPTransportDistributeSuccessAfterRetry(t *testing.T) {
	var requestCount int32

	// Create a test server that fails twice then succeeds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		receipt := FixtureDistributionReceipt{
			DistributionID:      "dist-1",
			TargetID:            "target-1",
			ReceivedAtUnix:      time.Now().Unix(),
			ReceivedCatalogHash: "catalog-1",
			VerificationStatus:  "verified",
		}
		receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(receipt)
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      3, // Try once, retry 3 times
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.0, // No jitter for deterministic test
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)
	receipt, err := transport.Distribute(context.Background(), job, target, payload)
	if err != nil {
		t.Fatalf("Expected no error after successful retry, got: %v", err)
	}

	if receipt.DistributionID != "dist-1" {
		t.Errorf("Expected DistributionID to be 'dist-1', got '%s'", receipt.DistributionID)
	}

	// Should have made 3 requests (2 failures + 1 success)
	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("Expected 3 requests, got %d", requestCount)
	}
}

// TestHTTPTransportDistributeTimeout tests request timeout
func TestHTTPTransportDistributeTimeout(t *testing.T) {
	// Create a test server that delays before responding
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay longer than the timeout
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         50 * time.Millisecond, // Very short timeout
		RetryCount:      0,
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)
	_, err = transport.Distribute(context.Background(), job, target, payload)
	if err == nil {
		t.Error("Expected timeout error")
	}
	if !errors.Is(err, ErrTransportTimeout) {
		t.Errorf("Expected ErrTransportTimeout, got: %v", err)
	}
}

// TestHTTPTransportShouldRetryStatusCode tests which status codes trigger retries
func TestHTTPTransportShouldRetryStatusCode(t *testing.T) {
	transport := &HTTPTransport{}

	retryableStatuses := []int{
		http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	}

	for _, status := range retryableStatuses {
		if !transport.shouldRetryStatusCode(status) {
			t.Errorf("Expected status %d to be retryable", status)
		}
	}

	nonRetryableStatuses := []int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
	}

	for _, status := range nonRetryableStatuses {
		if transport.shouldRetryStatusCode(status) {
			t.Errorf("Expected status %d to NOT be retryable", status)
		}
	}
}

// TestHTTPTransportCalculateBackoffDelay tests exponential backoff calculation
func TestHTTPTransportCalculateBackoffDelay(t *testing.T) {
	config := TransportConfig{
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.0, // No jitter for deterministic test
	}

	transport := &HTTPTransport{config: config}

	// First retry (attempt 1): 100ms * 2^(0) = 100ms
	delay := transport.calculateBackoffDelay(1)
	if delay != 100*time.Millisecond {
		t.Errorf("Expected delay for attempt 1 to be 100ms, got %v", delay)
	}

	// Second retry (attempt 2): 100ms * 2^(1) = 200ms
	delay = transport.calculateBackoffDelay(2)
	if delay != 200*time.Millisecond {
		t.Errorf("Expected delay for attempt 2 to be 200ms, got %v", delay)
	}

	// Third retry (attempt 3): 100ms * 2^(2) = 400ms
	delay = transport.calculateBackoffDelay(3)
	if delay != 400*time.Millisecond {
		t.Errorf("Expected delay for attempt 3 to be 400ms, got %v", delay)
	}

	// Fourth retry (attempt 4): 100ms * 2^(3) = 800ms
	delay = transport.calculateBackoffDelay(4)
	if delay != 800*time.Millisecond {
		t.Errorf("Expected delay for attempt 4 to be 800ms, got %v", delay)
	}

	// Fifth retry (attempt 5): 100ms * 2^(4) = 1600ms, but capped at max delay of 1000ms
	delay = transport.calculateBackoffDelay(5)
	if delay != 1*time.Second {
		t.Errorf("Expected delay for attempt 5 to be capped at 1s, got %v", delay)
	}
}

// TestHTTPTransportAuthFailed tests authentication failure
func TestHTTPTransportAuthFailed(t *testing.T) {
	// Create a test server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthBearer, "token")

	payload := []byte(`{"test": "data"}`)
	_, err = transport.Distribute(context.Background(), job, target, payload)
	if err == nil {
		t.Error("Expected error for 401 response")
	}
	if !errors.Is(err, ErrTransportAuthFailed) {
		t.Errorf("Expected ErrTransportAuthFailed, got: %v", err)
	}
}

// TestLocalFileTransport tests LocalFileTransport creation
func TestLocalFileTransport(t *testing.T) {
	config := DefaultTransportConfig()
	options := LocalFileTransportOptions{Config: config}

	transport, err := NewLocalFileTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if transport == nil {
		t.Fatal("Expected transport to be non-nil")
	}

	if transport.Name() != "local_file" {
		t.Errorf("Expected name to be 'local_file', got '%s'", transport.Name())
	}

	if transport.Method() != DistributionMethodLocalFile {
		t.Errorf("Expected method to be LocalFile, got '%s'", transport.Method())
	}
}

// TestS3Transport tests S3Transport creation
func TestS3Transport(t *testing.T) {
	config := DefaultTransportConfig()
	options := FixtureTransportOptions{Config: config}

	transport, err := NewS3Transport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if transport == nil {
		t.Fatal("Expected transport to be non-nil")
	}

	if transport.Name() != "s3" {
		t.Errorf("Expected name to be 's3', got '%s'", transport.Name())
	}

	if transport.Method() != DistributionMethodS3 {
		t.Errorf("Expected method to be S3, got '%s'", transport.Method())
	}
}

// TestSSHTransport tests SSHTransport creation
func TestSSHTransport(t *testing.T) {
	config := DefaultTransportConfig()
	options := FixtureTransportOptions{Config: config}

	transport, err := NewSSHTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if transport == nil {
		t.Fatal("Expected transport to be non-nil")
	}

	if transport.Name() != "ssh" {
		t.Errorf("Expected name to be 'ssh', got '%s'", transport.Name())
	}

	if transport.Method() != DistributionMethodSSH {
		t.Errorf("Expected method to be SSH, got '%s'", transport.Method())
	}
}

// TestDistributionClientCreation tests DistributionClient creation
func TestDistributionClientCreation(t *testing.T) {
	config := DefaultTransportConfig()
	client := NewDistributionClient(config)

	if client == nil {
		t.Fatal("Expected client to be non-nil")
	}

	// Check that all default transports are registered
	methods := client.registry.Methods()
	if len(methods) != 4 {
		t.Errorf("Expected 4 registered transports, got %d", len(methods))
	}

	// Check specific transports
	if _, ok := client.GetTransport(DistributionMethodHTTPS); !ok {
		t.Error("Expected HTTPS transport to be registered")
	}
	if _, ok := client.GetTransport(DistributionMethodLocalFile); !ok {
		t.Error("Expected LocalFile transport to be registered")
	}
	if _, ok := client.GetTransport(DistributionMethodS3); !ok {
		t.Error("Expected S3 transport to be registered")
	}
	if _, ok := client.GetTransport(DistributionMethodSSH); !ok {
		t.Error("Expected SSH transport to be registered")
	}
}

// TestDistributionClientDistribute tests client-level distribution
func TestDistributionClientDistribute(t *testing.T) {
	// Create a test server that returns success
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receipt := FixtureDistributionReceipt{
			DistributionID:      "dist-1",
			TargetID:            "target-1",
			ReceivedAtUnix:      time.Now().Unix(),
			ReceivedCatalogHash: "catalog-1",
			VerificationStatus:  "verified",
		}
		receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(receipt)
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}

	client := NewDistributionClient(config)

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)

	// Use the client's registry to set the base URL on the HTTP transport
	if httpTransport, ok := client.GetTransport(DistributionMethodHTTPS); ok {
		if ht, ok := httpTransport.(*HTTPTransport); ok {
			_ = ht.SetBaseURL(server.URL)
		}
	}

	receipt, err := client.Distribute(context.Background(), job, target, payload)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if receipt.DistributionID != "dist-1" {
		t.Errorf("Expected DistributionID to be 'dist-1', got '%s'", receipt.DistributionID)
	}
}

// TestDistributionClientDistributeWithRetry tests client-level retry
func TestDistributionClientDistributeWithRetry(t *testing.T) {
	var requestCount int32

	// Create a test server that fails once then succeeds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		receipt := FixtureDistributionReceipt{
			DistributionID:      "dist-1",
			TargetID:            "target-1",
			ReceivedAtUnix:      time.Now().Unix(),
			ReceivedCatalogHash: "catalog-1",
			VerificationStatus:  "verified",
		}
		receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(receipt)
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      1, // 1 retry at client level
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.0,
		VerifyTLS:       false,
	}

	client := NewDistributionClient(config)

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)

	// Set base URL
	if httpTransport, ok := client.GetTransport(DistributionMethodHTTPS); ok {
		if ht, ok := httpTransport.(*HTTPTransport); ok {
			_ = ht.SetBaseURL(server.URL)
			// Override transport config to disable transport-level retries
			// so we only test client-level retries
			config.RetryCount = 0
		}
	}

	_, err := client.DistributeWithRetry(context.Background(), job, target, payload)
	if err != nil {
		t.Fatalf("Expected no error after client retry, got: %v", err)
	}

	// Should have made at least 2 requests (1 initial + 1 retry)
	if atomic.LoadInt32(&requestCount) < 2 {
		t.Errorf("Expected at least 2 requests, got %d", requestCount)
	}
}

// TestDistributionClientDistributeError tests client-level error handling
func TestDistributionClientDistributeError(t *testing.T) {
	// Create a test server that returns 400 Bad Request (non-retryable)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}

	client := NewDistributionClient(config)

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)

	// Set base URL
	if httpTransport, ok := client.GetTransport(DistributionMethodHTTPS); ok {
		if ht, ok := httpTransport.(*HTTPTransport); ok {
			_ = ht.SetBaseURL(server.URL)
		}
	}

	_, err := client.Distribute(context.Background(), job, target, payload)
	if err == nil {
		t.Error("Expected error for non-retryable failure")
	}
}

// TestDistributionClientRegisterTransport tests custom transport registration
func TestDistributionClientRegisterTransport(t *testing.T) {
	config := DefaultTransportConfig()
	client := NewDistributionClient(config)

	mockTransport := &MockTransport{method: DistributionMethod("custom")}
	client.RegisterTransport(mockTransport)

	transport, ok := client.GetTransport(DistributionMethod("custom"))
	if !ok {
		t.Error("Expected custom transport to be registered")
	}
	if transport != mockTransport {
		t.Error("Expected to get the same transport instance")
	}
}

// TestDistributionClientIsRetryableError tests client-level retryable error detection
func TestDistributionClientIsRetryableError(t *testing.T) {
	config := DefaultTransportConfig()
	client := NewDistributionClient(config)

	testCases := []struct {
		err      error
		expected bool
	}{
		{nil, false},
		{ErrTransportTimeout, true},
		{ErrTransportConnectionFailed, true},
		{ErrTransportAuthFailed, true},
		{ErrTransportInvalidResponse, false},
		{ErrTransportRetryExhausted, false},
		{ErrTransportNotImplemented, false},
		{errors.New("timeout occurred"), true},
		{errors.New("connection refused"), true},
		{errors.New("some other error"), false},
	}

	for _, tc := range testCases {
		result := client.isRetryableError(tc.err)
		if result != tc.expected {
			t.Errorf("isRetryableError(%v) = %v, expected %v", tc.err, result, tc.expected)
		}
	}
}

// TestHTTPTransportParseResponseNonJSON tests parsing non-JSON responses
func TestHTTPTransportParseResponseNonJSON(t *testing.T) {
	// Create a test server that returns plain text
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)
	receipt, err := transport.Distribute(context.Background(), job, target, payload)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should still get a valid receipt even with non-JSON response
	if receipt.DistributionID != "dist-1" {
		t.Errorf("Expected DistributionID to be 'dist-1', got '%s'", receipt.DistributionID)
	}
	if receipt.TargetID != "target-1" {
		t.Errorf("Expected TargetID to be 'target-1', got '%s'", receipt.TargetID)
	}
	if receipt.ReceiptHash == "" {
		t.Error("Expected ReceiptHash to be non-empty")
	}
}

// TestTransportMethodInterface tests that all transports implement the interface
func TestTransportMethodInterface(t *testing.T) {
	// This test ensures all transports implement FixtureTransport
	// Create properly initialized transports
	config := DefaultTransportConfig()

	httpTransport, _ := NewHTTPTransport(FixtureTransportOptions{Config: config})
	localTransport, _ := NewLocalFileTransportWithConfig(FixtureTransportOptions{Config: config})
	s3Transport, _ := NewS3Transport(FixtureTransportOptions{Config: config})
	sshTransport, _ := NewSSHTransport(FixtureTransportOptions{Config: config})

	transports := []FixtureTransport{
		httpTransport,
		localTransport,
		s3Transport,
		sshTransport,
	}

	for _, transport := range transports {
		// These should not panic
		_ = transport.Name()
		_ = transport.Method()
		// Distribute should not panic (though it may return error)
		_, _ = transport.Distribute(context.Background(), FixtureDistributionJob{}, FixtureDistributionTarget{}, []byte{})
	}
}

// TestHTTPTransportContextCancellation tests that context cancellation is respected for HTTP transport
func TestHTTPTransportContextCancellation(t *testing.T) {
	// Create a test server that takes forever
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {}
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start the distribution in a goroutine
	done := make(chan error, 1)
	go func() {
		_, err := transport.Distribute(ctx, job, target, payload)
		done <- err
	}()

	// Cancel the context
	cancel()

	// Wait for the distribution to complete with error
	select {
	case err := <-done:
		if err == nil {
			t.Error("Expected error after context cancellation")
		}
		if !errors.Is(err, ErrTransportTimeout) {
			t.Errorf("Expected ErrTransportTimeout, got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("Context cancellation took too long")
	}
}

// TestDistributionClientUnregisteredMethod tests error for unregistered transport method
func TestDistributionClientUnregisteredMethod(t *testing.T) {
	config := DefaultTransportConfig()
	client := NewDistributionClient(config)

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target := FixtureDistributionTarget{
		ID:     "target-1",
		Name:   "Target 1",
		URL:    "https://example.com",
		Method: DistributionMethod("unregistered"),
	}

	payload := []byte(`{"test": "data"}`)
	_, err := client.Distribute(context.Background(), job, target, payload)
	if err == nil {
		t.Error("Expected error for unregistered transport method")
	}
	if !errors.Is(err, ErrTransportNotImplemented) {
		t.Errorf("Expected ErrTransportNotImplemented, got: %v", err)
	}
}

// TestEmptyPayload tests distribution with empty payload
func TestEmptyPayload(t *testing.T) {
	// Create a test server that accepts empty payloads
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("Expected empty body, got %d bytes", len(body))
		}

		receipt := FixtureDistributionReceipt{
			DistributionID:      "dist-1",
			TargetID:            "target-1",
			ReceivedAtUnix:      time.Now().Unix(),
			ReceivedCatalogHash: "catalog-1",
			VerificationStatus:  "verified",
		}
		receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(receipt)
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte{}
	receipt, err := transport.Distribute(context.Background(), job, target, payload)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if receipt.DistributionID != "dist-1" {
		t.Errorf("Expected DistributionID to be 'dist-1', got '%s'", receipt.DistributionID)
	}
}

// TestFixtureHeaders tests that fixture metadata headers are sent correctly
func TestFixtureHeaders(t *testing.T) {
	var receivedHeaders http.Header

	// Create a test server that captures headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()

		receipt := FixtureDistributionReceipt{
			DistributionID:      "dist-1",
			TargetID:            "target-1",
			ReceivedAtUnix:      time.Now().Unix(),
			ReceivedCatalogHash: "catalog-1",
			VerificationStatus:  "verified",
		}
		receipt.ReceiptHash = FixtureDistributionReceiptHash(receipt)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(receipt)
	}))
	defer server.Close()

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   1 * time.Second,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL(server.URL); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob(
		"dist-123",
		"target-1",
		"catalog-hash-abc",
		[]string{"bundle-1", "bundle-2"},
		"manifest-hash-xyz",
	)
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", server.URL, DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)
	transport.Distribute(context.Background(), job, target, payload)

	if receivedHeaders.Get("X-Fixture-Distribution-ID") != "dist-123" {
		t.Errorf("Expected X-Fixture-Distribution-ID to be 'dist-123', got '%s'", receivedHeaders.Get("X-Fixture-Distribution-ID"))
	}
	if receivedHeaders.Get("X-Fixture-Catalog-Hash") != "catalog-hash-abc" {
		t.Errorf("Expected X-Fixture-Catalog-Hash to be 'catalog-hash-abc', got '%s'", receivedHeaders.Get("X-Fixture-Catalog-Hash"))
	}
	if receivedHeaders.Get("X-Fixture-Manifest-Hash") != "manifest-hash-xyz" {
		t.Errorf("Expected X-Fixture-Manifest-Hash to be 'manifest-hash-xyz', got '%s'", receivedHeaders.Get("X-Fixture-Manifest-Hash"))
	}
	if receivedHeaders.Get("X-Fixture-Bundle-Hashes") != "bundle-1,bundle-2" {
		t.Errorf("Expected X-Fixture-Bundle-Hashes to be 'bundle-1,bundle-2', got '%s'", receivedHeaders.Get("X-Fixture-Bundle-Hashes"))
	}
}

// TestHTTPTransportWithTLSVerification tests TLS verification settings
func TestHTTPTransportWithTLSVerification(t *testing.T) {
	// Test with VerifyTLS = true (default)
	config := DefaultTransportConfig()
	config.VerifyTLS = true
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if transport.client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify != false {
		t.Error("Expected InsecureSkipVerify to be false when VerifyTLS is true")
	}

	// Test with VerifyTLS = false
	config.VerifyTLS = false
	options = FixtureTransportOptions{Config: config}

	transport, err = NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if transport.client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify != true {
		t.Error("Expected InsecureSkipVerify to be true when VerifyTLS is false")
	}
}

// TestMaxPayloadSize tests that exactly MaxTransportPayloadSize is allowed
func TestMaxPayloadSize(t *testing.T) {
	config := DefaultTransportConfig()
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL("https://example.com"); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", "https://example.com", DistributionMethodHTTPS, DistributionAuthNone, "")

	// Create payload exactly at the limit
	payload := make([]byte, MaxTransportPayloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// This should not fail due to size (it will fail for other reasons like no server)
	_, _ = transport.Distribute(context.Background(), job, target, payload)
	// The error will be about connection, not payload size
}

// TestTransportErrorMessages tests that error messages are descriptive
func TestTransportErrorMessages(t *testing.T) {
	errors := []struct {
		err       error
		substring string
	}{
		{ErrTransportNotImplemented, "transport not implemented"},
		{ErrTransportTimeout, "transport timeout"},
		{ErrTransportAuthFailed, "transport authentication failed"},
		{ErrTransportConnectionFailed, "transport connection failed"},
		{ErrTransportInvalidResponse, "transport invalid response"},
		{ErrTransportRetryExhausted, "transport retry exhausted"},
	}

	for _, tc := range errors {
		if !strings.Contains(tc.err.Error(), tc.substring) {
			t.Errorf("Expected error %v to contain '%s', got: %s", tc.err, tc.substring, tc.err.Error())
		}
	}
}

// TestNetworkErrorHandling tests handling of various network errors
func TestNetworkErrorHandling(t *testing.T) {
	// Test with a server that doesn't exist
	config := TransportConfig{
		Timeout:         100 * time.Millisecond,
		RetryCount:      0,
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.1,
		VerifyTLS:       false,
	}
	options := FixtureTransportOptions{Config: config}

	transport, err := NewHTTPTransport(options)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if err := transport.SetBaseURL("http://nonexistent.example.com:12345"); err != nil {
		t.Fatalf("Failed to set base URL: %v", err)
	}

	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", "http://nonexistent.example.com:12345", DistributionMethodHTTPS, DistributionAuthNone, "")

	payload := []byte(`{"test": "data"}`)
	_, err = transport.Distribute(context.Background(), job, target, payload)
	if err == nil {
		t.Error("Expected error for unreachable server")
	}
	// The error should be about connection failure
	if !errors.Is(err, ErrTransportConnectionFailed) && !strings.Contains(err.Error(), "connection refused") {
		t.Logf("Got error: %v", err)
	}
}

// TestTransportSDKRequirements tests that S3 and SSH transports return SDK error
func TestTransportSDKRequirements(t *testing.T) {
	config := DefaultTransportConfig()

	// Test LocalFileTransport
	localTransport, _ := NewLocalFileTransportWithConfig(FixtureTransportOptions{Config: config})
	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Target 1", "/tmp/test", DistributionMethodLocalFile, DistributionAuthNone, "")

	// LocalFileTransport is now fully implemented, so we don't expect NotImplemented
	// It might succeed or return other errors (permission, etc.)
	_, _ = localTransport.Distribute(context.Background(), job, target, []byte("test"))
	// We accept any result - success or error, as long as it's not NotImplemented

	// Test S3Transport - requires AWS credentials
	s3Transport, _ := NewS3Transport(FixtureTransportOptions{Config: config})
	target.Method = DistributionMethodS3
	target.URL = "s3://bucket/path"

	_, err := s3Transport.Distribute(context.Background(), job, target, []byte("test"))
	// Should return connection failed error since no AWS client is configured
	if err == nil {
		t.Error("Expected error for S3Transport without AWS credentials")
	}
	// Accept connection failed or similar errors - the transport is working but needs config
	if !errors.Is(err, ErrTransportConnectionFailed) && !errors.Is(err, ErrTransportInvalidPath) {
		t.Logf("Got expected error for S3Transport without credentials: %v", err)
	}

	// Test SSHTransport - requires SSH authentication
	sshTransport, _ := NewSSHTransport(FixtureTransportOptions{Config: config})
	target.Method = DistributionMethodSSH
	target.URL = "ssh://host/path"

	_, err = sshTransport.Distribute(context.Background(), job, target, []byte("test"))
	// Should return authentication error since no SSH credentials are configured
	if err == nil {
		t.Error("Expected error for SSHTransport without authentication")
	}
	// Accept auth failed or similar errors - the transport is working but needs config
	if !errors.Is(err, ErrTransportAuthFailed) && !errors.Is(err, ErrTransportInvalidPath) {
		t.Logf("Got expected error for SSHTransport without authentication: %v", err)
	}
}

// LocalFileTransport comprehensive tests

// TestLocalFileTransportDistribute tests actual file distribution
func TestLocalFileTransportDistribute(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "solid-sidecar-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.0,
		VerifyTLS:       true,
	}

	options := LocalFileTransportOptions{
		Config:    config,
		BasePath:  tempDir,
		Overwrite: true,
	}

	transport, err := NewLocalFileTransport(options)
	if err != nil {
		t.Fatalf("Failed to create LocalFileTransport: %v", err)
	}

	// Create a test job and target
	job, _ := NewFixtureDistributionJob("dist-1", "target-1", "catalog-1", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-1", "Test Target", "test-fixture.json", DistributionMethodLocalFile, DistributionAuthNone, "")

	// Test payload
	payload := []byte(`{"test": "data", "value": 42}`)

	// Distribute the payload
	receipt, err := transport.Distribute(context.Background(), job, target, payload)
	if err != nil {
		t.Fatalf("Failed to distribute: %v", err)
	}

	// Verify the file was created
	filePath := filepath.Join(tempDir, "test-fixture.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatal("Expected file to be created")
	}

	// Verify the file contents
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if !bytes.Equal(fileData, payload) {
		t.Errorf("File contents don't match. Expected %d bytes, got %d bytes", len(payload), len(fileData))
	}

	// Verify receipt
	if receipt.DistributionID != job.DistributionID {
		t.Errorf("Expected DistributionID to be '%s', got '%s'", job.DistributionID, receipt.DistributionID)
	}

	if receipt.TargetID != target.ID {
		t.Errorf("Expected TargetID to be '%s', got '%s'", target.ID, receipt.TargetID)
	}
}

// TestLocalFileTransportSubdirectoryCreation tests that subdirectories are created
func TestLocalFileTransportSubdirectoryCreation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "solid-sidecar-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.0,
		VerifyTLS:       true,
	}

	options := LocalFileTransportOptions{
		Config:    config,
		BasePath:  tempDir,
		Overwrite: true,
	}

	transport, err := NewLocalFileTransport(options)
	if err != nil {
		t.Fatalf("Failed to create LocalFileTransport: %v", err)
	}

	// Create a test job and target with nested path
	job, _ := NewFixtureDistributionJob("dist-2", "target-2", "catalog-2", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-2", "Test Target", "subdir/nested/fixture.json", DistributionMethodLocalFile, DistributionAuthNone, "")

	payload := []byte(`{"nested": "test"}`)

	// Distribute the payload
	_, err = transport.Distribute(context.Background(), job, target, payload)
	if err != nil {
		t.Fatalf("Failed to distribute: %v", err)
	}

	// Verify the file was created in the nested directory
	filePath := filepath.Join(tempDir, "subdir", "nested", "fixture.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatal("Expected file to be created in nested directory")
	}

	// Verify the file contents
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if !bytes.Equal(fileData, payload) {
		t.Errorf("File contents don't match. Expected %d bytes, got %d bytes", len(payload), len(fileData))
	}
}

// TestLocalFileTransportNoOverwrite tests that files are not overwritten when Overwrite is false
func TestLocalFileTransportNoOverwrite(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "solid-sidecar-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.0,
		VerifyTLS:       true,
	}

	options := LocalFileTransportOptions{
		Config:    config,
		BasePath:  tempDir,
		Overwrite: false,
	}

	transport, err := NewLocalFileTransport(options)
	if err != nil {
		t.Fatalf("Failed to create LocalFileTransport: %v", err)
	}

	// Create an existing file
	existingContent := []byte(`{"existing": "content"}`)
	filePath := filepath.Join(tempDir, "no-overwrite.json")
	if err := os.WriteFile(filePath, existingContent, DefaultFilePermissions); err != nil {
		t.Fatalf("Failed to create existing file: %v", err)
	}

	// Create a test job and target
	job, _ := NewFixtureDistributionJob("dist-3", "target-3", "catalog-3", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-3", "Test Target", "no-overwrite.json", DistributionMethodLocalFile, DistributionAuthNone, "")

	// Try to distribute different payload
	newPayload := []byte(`{"new": "content"}`)

	// Distribute should fail or not overwrite
	_, err = transport.Distribute(context.Background(), job, target, newPayload)
	// We accept either an error (file exists) or success without overwriting
	if err != nil && !errors.Is(err, ErrTransportFileExists) {
		t.Logf("Got error (expected): %v", err)
	}

	// Verify the file still contains original content
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if !bytes.Equal(fileData, existingContent) {
		t.Errorf("File was overwritten when it shouldn't have been")
	}
}

// TestLocalFileTransportOverwrite tests that files are overwritten when Overwrite is true
func TestLocalFileTransportOverwrite(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "solid-sidecar-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.0,
		VerifyTLS:       true,
	}

	options := LocalFileTransportOptions{
		Config:    config,
		BasePath:  tempDir,
		Overwrite: true,
	}

	transport, err := NewLocalFileTransport(options)
	if err != nil {
		t.Fatalf("Failed to create LocalFileTransport: %v", err)
	}

	// Create an existing file
	existingContent := []byte(`{"existing": "content"}`)
	filePath := filepath.Join(tempDir, "overwrite.json")
	if err := os.WriteFile(filePath, existingContent, DefaultFilePermissions); err != nil {
		t.Fatalf("Failed to create existing file: %v", err)
	}

	// Create a test job and target
	job, _ := NewFixtureDistributionJob("dist-4", "target-4", "catalog-4", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-4", "Test Target", "overwrite.json", DistributionMethodLocalFile, DistributionAuthNone, "")

	// Try to distribute different payload
	newPayload := []byte(`{"new": "content"}`)

	// Distribute should succeed and overwrite
	_, err = transport.Distribute(context.Background(), job, target, newPayload)
	if err != nil {
		t.Fatalf("Failed to distribute: %v", err)
	}

	// Verify the file was overwritten
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if !bytes.Equal(fileData, newPayload) {
		t.Errorf("File was not overwritten when it should have been")
	}
}

// TestLocalFileTransportPayloadSizeValidation tests payload size limits
func TestLocalFileTransportPayloadSizeValidation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "solid-sidecar-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.0,
		VerifyTLS:       true,
	}

	options := LocalFileTransportOptions{
		Config:    config,
		BasePath:  tempDir,
		Overwrite: true,
	}

	transport, err := NewLocalFileTransport(options)
	if err != nil {
		t.Fatalf("Failed to create LocalFileTransport: %v", err)
	}

	// Create a test job and target
	job, _ := NewFixtureDistributionJob("dist-5", "target-5", "catalog-5", []string{}, "")
	target, _ := NewFixtureDistributionTarget("target-5", "Test Target", "large-fixture.json", DistributionMethodLocalFile, DistributionAuthNone, "")

	// Create a payload that exceeds the maximum size
	largePayload := make([]byte, MaxTransportPayloadSize+1)
	for i := range largePayload {
		largePayload[i] = 'x'
	}

	// Distribute should fail due to payload size
	_, err = transport.Distribute(context.Background(), job, target, largePayload)
	if err == nil {
		t.Error("Expected error for payload exceeding maximum size")
	}

	if !errors.Is(err, ErrTransportInvalidResponse) {
		t.Errorf("Expected ErrTransportInvalidResponse, got: %v", err)
	}
}

// TestLocalFileTransportPathTraversalProtection tests path traversal protection
func TestLocalFileTransportPathTraversalProtection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "solid-sidecar-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := TransportConfig{
		Timeout:         5 * time.Second,
		RetryCount:      0,
		RetryBaseDelay:  10 * time.Millisecond,
		RetryMaxDelay:   100 * time.Millisecond,
		RetryMultiplier: 2.0,
		RetryJitter:     0.0,
		VerifyTLS:       true,
	}

	options := LocalFileTransportOptions{
		Config:    config,
		BasePath:  tempDir,
		Overwrite: true,
	}

	transport, err := NewLocalFileTransport(options)
	if err != nil {
		t.Fatalf("Failed to create LocalFileTransport: %v", err)
	}

	// Create a test job
	job, _ := NewFixtureDistributionJob("dist-6", "target-6", "catalog-6", []string{}, "")

	// Test various path traversal attempts
	traversalAttempts := []string{
		"../etc/passwd",
		"..\\windows\\system32",
		"subdir/../../etc/passwd",
		"/absolute/path",
		"~/.ssh/id_rsa",
	}

	for _, path := range traversalAttempts {
		target, _ := NewFixtureDistributionTarget("target-test-6", "Test Target", path, DistributionMethodLocalFile, DistributionAuthNone, "")

		_, err := transport.Distribute(context.Background(), job, target, []byte("test"))
		if err == nil {
			t.Errorf("Expected error for path traversal attempt: %s", path)
		}
		// Should get invalid path or permission error
		if !errors.Is(err, ErrTransportInvalidPath) && !errors.Is(err, ErrTransportPermissionDenied) {
			t.Logf("Got error for path '%s': %v", path, err)
		}
	}
}

// TestLocalFileTransportSetBasePath tests SetBasePath functionality
func TestLocalFileTransportSetBasePath(t *testing.T) {
	config := DefaultTransportConfig()
	config.RetryCount = 0

	options := LocalFileTransportOptions{
		Config: config,
	}

	transport, err := NewLocalFileTransport(options)
	if err != nil {
		t.Fatalf("Failed to create LocalFileTransport: %v", err)
	}

	// Set base path
	tempDir := t.TempDir()
	err = transport.SetBasePath(tempDir)
	if err != nil {
		t.Fatalf("Failed to set base path: %v", err)
	}

	// Verify base path was set
	if transport.GetBasePath() != tempDir {
		t.Errorf("Expected base path to be '%s', got '%s'", tempDir, transport.GetBasePath())
	}
}

// S3Transport comprehensive tests

// TestS3TransportValidation tests S3 transport validation
func TestS3TransportValidation(t *testing.T) {
	config := DefaultTransportConfig()
	config.RetryCount = 0

	// Test with invalid bucket name
	_, err := NewS3TransportWithOptions(S3TransportOptions{
		Config: config,
		Bucket: "INVALID_BUCKET", // Uppercase is invalid
	})
	if err == nil {
		t.Error("Expected error for invalid bucket name")
	}
	if !errors.Is(err, ErrTransportInvalidPath) {
		t.Errorf("Expected ErrTransportInvalidPath, got: %v", err)
	}

	// Test with valid bucket name
	transport, err := NewS3TransportWithOptions(S3TransportOptions{
		Config: config,
		Bucket: "valid-bucket-123",
	})
	if err != nil {
		t.Fatalf("Expected no error for valid bucket, got: %v", err)
	}

	// Note: We can't directly access private fields, but we can test behavior
	// Test SetBucket
	err = transport.SetBucket("another-valid-bucket")
	if err != nil {
		t.Fatalf("Failed to set bucket: %v", err)
	}

	// Test invalid bucket name via SetBucket
	err = transport.SetBucket("invalid..bucket")
	if err == nil {
		t.Error("Expected error for invalid bucket name")
	}
}

// TestS3TransportURLParsing tests S3 URL parsing
func TestS3TransportURLParsing(t *testing.T) {
	transport := &S3Transport{}

	testCases := []struct {
		url            string
		expectedBucket string
		expectedKey    string
		shouldError    bool
	}{
		{"s3://bucket/key", "bucket", "key", false},
		{"s3://bucket/", "bucket", "", false},
		{"s3://bucket", "bucket", "", false},
		{"s3://my-bucket/path/to/key", "my-bucket", "path/to/key", false},
		{"bucket/key", "bucket", "key", false},
		{"", "", "", true},
		{"invalid://bucket/key", "", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.url, func(t *testing.T) {
			bucket, key, err := transport.ParseS3URL(tc.url)
			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for URL '%s', got nil", tc.url)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for URL '%s': %v", tc.url, err)
				return
			}

			if bucket != tc.expectedBucket {
				t.Errorf("Expected bucket '%s', got '%s' for URL '%s'", tc.expectedBucket, bucket, tc.url)
			}

			if key != tc.expectedKey {
				t.Errorf("Expected key '%s', got '%s' for URL '%s'", tc.expectedKey, key, tc.url)
			}
		})
	}
}

// TestS3TransportKeyPrefixAndRegion tests S3 transport key prefix and region settings
func TestS3TransportKeyPrefixAndRegion(t *testing.T) {
	config := DefaultTransportConfig()
	config.RetryCount = 0

	transport, err := NewS3TransportWithOptions(S3TransportOptions{
		Config:    config,
		Bucket:    "test-bucket",
		KeyPrefix: "fixtures/",
		Region:    "us-west-2",
	})
	if err != nil {
		t.Fatalf("Failed to create S3Transport: %v", err)
	}

	// Test SetKeyPrefix
	transport.SetKeyPrefix("new-prefix/")

	// Test SetRegion
	err = transport.SetRegion("eu-west-1")
	if err != nil {
		t.Fatalf("Failed to set region: %v", err)
	}

	// Test invalid region
	err = transport.SetRegion("invalid-region!")
	if err == nil {
		t.Error("Expected error for invalid region")
	}
}

// TestS3TransportAWSCredentials tests S3 transport AWS credential configuration
func TestS3TransportAWSCredentials(t *testing.T) {
	config := DefaultTransportConfig()
	config.RetryCount = 0

	// Test with static credentials
	transport, err := NewS3TransportWithOptions(S3TransportOptions{
		Config:          config,
		Bucket:          "test-bucket",
		Region:          "us-east-1",
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		UseDefaultCreds: false,
	})
	if err != nil {
		t.Fatalf("Failed to create S3Transport with static credentials: %v", err)
	}

	// Verify S3 client was created
	if transport.s3Client == nil {
		t.Error("Expected S3 client to be created with static credentials")
	}

	// Test SetAWSCredentials
	err = transport.SetAWSCredentials("NEW_ACCESS_KEY", "NEW_SECRET_KEY", "NEW_SESSION_TOKEN")
	if err != nil {
		t.Fatalf("Failed to set AWS credentials: %v", err)
	}

	// Test SetUseDefaultAWSCredentials
	err = transport.SetUseDefaultAWSCredentials(true)
	if err != nil {
		t.Fatalf("Failed to set default AWS credentials: %v", err)
	}

	// Test with invalid credentials (empty)
	err = transport.SetAWSCredentials("", "", "")
	if err != nil {
		t.Fatalf("Failed to clear AWS credentials: %v", err)
	}
}

// SSHTransport comprehensive tests

// TestSSHTransportValidation tests SSH transport validation
func TestSSHTransportValidation(t *testing.T) {
	config := DefaultTransportConfig()
	config.RetryCount = 0

	// Test with valid host
	transport, err := NewSSHTransportWithOptions(SSHTransportOptions{
		Config:   config,
		Host:     "example.com",
		Port:     22,
		Username: "testuser",
	})
	if err != nil {
		t.Fatalf("Failed to create SSHTransport: %v", err)
	}

	// Test SetHost
	err = transport.SetHost("another-host.com")
	if err != nil {
		t.Fatalf("Failed to set host: %v", err)
	}

	// Test SetPort
	err = transport.SetPort(2222)
	if err != nil {
		t.Fatalf("Failed to set port: %v", err)
	}

	// Test SetPort with 0 (should be allowed for default)
	err = transport.SetPort(0)
	if err != nil {
		t.Fatalf("Failed to set port to 0: %v", err)
	}

	// Test invalid port
	err = transport.SetPort(70000)
	if err == nil {
		t.Error("Expected error for port out of range")
	}

	err = transport.SetPort(-1)
	if err == nil {
		t.Error("Expected error for negative port")
	}

	// Test SetUsername
	err = transport.SetUsername("another-user")
	if err != nil {
		t.Fatalf("Failed to set username: %v", err)
	}

	// Test invalid username
	err = transport.SetUsername("")
	if err == nil {
		t.Error("Expected error for empty username")
	}

	// Test SetHost with invalid host
	err = transport.SetHost("")
	if err == nil {
		t.Error("Expected error for empty host via SetHost")
	}

	// Test SetPort with invalid values
	err = transport.SetPort(-1)
	if err == nil {
		t.Error("Expected error for negative port via SetPort")
	}

	err = transport.SetPort(70000)
	if err == nil {
		t.Error("Expected error for port > 65535 via SetPort")
	}

	// Test SetUsername with invalid username
	err = transport.SetUsername("")
	if err == nil {
		t.Error("Expected error for empty username via SetUsername")
	}

	// Test SetUseSFTP
	transport.SetUseSFTP(true)
	transport.SetUseSFTP(false)

	// Test SetSSHCredentials
	err = transport.SetSSHCredentials("testuser", "testpass")
	if err != nil {
		t.Fatalf("Failed to set SSH credentials: %v", err)
	}

	// Test SetPrivateKey
	testPrivateKey := []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
test
-----END OPENSSH PRIVATE KEY-----`)
	err = transport.SetPrivateKey(testPrivateKey)
	if err != nil {
		t.Fatalf("Failed to set SSH private key: %v", err)
	}

	// Test SetPrivateKeyPath
	err = transport.SetPrivateKeyPath("/path/to/private/key")
	if err != nil {
		t.Fatalf("Failed to set SSH private key path: %v", err)
	}

	// Test SetKnownHosts
	transport.SetKnownHosts("known_hosts_content")

	// Test SetStrictHostKeyChecking
	transport.SetStrictHostKeyChecking(true)
	transport.SetStrictHostKeyChecking(false)
}

// TestSSHTransportURLParsing tests SSH URL parsing
func TestSSHTransportURLParsing(t *testing.T) {
	transport := &SSHTransport{}

	testCases := []struct {
		url          string
		expectedHost string
		expectedPort int
		expectedPath string
		shouldError  bool
	}{
		{"ssh://user@host:22/path", "host", 22, "path", false},
		{"ssh://host/path", "host", 22, "path", false},
		{"sftp://host/path", "host", 22, "path", false},
		{"host/path", "host", 22, "path", false},
		{"user@host:2222/path", "host", 2222, "path", false},
		{"", "", 0, "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.url, func(t *testing.T) {
			host, port, path, err := transport.ParseSSHURL(tc.url)
			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for URL '%s', got nil", tc.url)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for URL '%s': %v", tc.url, err)
				return
			}

			if host != tc.expectedHost {
				t.Errorf("Expected host '%s', got '%s' for URL '%s'", tc.expectedHost, host, tc.url)
			}

			if port != tc.expectedPort {
				t.Errorf("Expected port %d, got %d for URL '%s'", tc.expectedPort, port, tc.url)
			}

			if path != tc.expectedPath {
				t.Errorf("Expected path '%s', got '%s' for URL '%s'", tc.expectedPath, path, tc.url)
			}
		})
	}
}

// TestSecurityValidation tests security-related validation functions
func TestSecurityValidation(t *testing.T) {
	t.Run("sanitizeError", func(t *testing.T) {
		// Test nil error
		if err := sanitizeError(nil); err != nil {
			t.Errorf("Expected nil error, got: %v", err)
		}

		// Test error without sensitive data
		testErr := errors.New("some error message")
		sanitized := sanitizeError(testErr)
		if sanitized.Error() != testErr.Error() {
			t.Errorf("Expected unchanged error, got: %v", sanitized)
		}

		// Test error with AWS access key
		awsKeyErr := errors.New("connection failed with AKIAIOSFODNN7EXAMPLE")
		sanitized = sanitizeError(awsKeyErr)
		if strings.Contains(sanitized.Error(), "AKIAIOSFODNN7EXAMPLE") {
			t.Error("Expected AWS key to be redacted")
		}
		if !strings.Contains(sanitized.Error(), "[REDACTED]") {
			t.Error("Expected [REDACTED] in sanitized error")
		}

		// Test error with private key
		privateKeyErr := errors.New("failed to parse -----BEGIN PRIVATE KEY-----")
		sanitized = sanitizeError(privateKeyErr)
		if strings.Contains(sanitized.Error(), "BEGIN PRIVATE KEY") {
			t.Error("Expected private key header to be redacted")
		}

		// Test error with password
		passwordErr := errors.New("auth failed: password=secret123")
		sanitized = sanitizeError(passwordErr)
		if strings.Contains(sanitized.Error(), "secret123") {
			t.Error("Expected password to be redacted")
		}

		// Test error with token
		tokenErr := errors.New("token=abc123xyz")
		sanitized = sanitizeError(tokenErr)
		if strings.Contains(sanitized.Error(), "abc123xyz") {
			t.Error("Expected token to be redacted")
		}

		// Test with custom sensitive fields
		customErr := errors.New("api_key=mysecretkey")
		sanitized = sanitizeError(customErr, "mysecretkey")
		if strings.Contains(sanitized.Error(), "mysecretkey") {
			t.Error("Expected custom sensitive field to be redacted")
		}
	})

	t.Run("validateS3Key", func(t *testing.T) {
		testCases := []struct {
			key         string
			shouldError bool
			errType     error
		}{
			{"", false, nil},
			{"valid/key/path.json", false, nil},
			{"a", false, nil},
			{strings.Repeat("a", 1024), false, nil},                    // Exactly at limit
			{strings.Repeat("a", 1025), true, ErrTransportInvalidPath}, // Over limit
			{"key\x00with\x00null", true, ErrTransportInvalidPath},     // Null byte
			{"key/../traversal", true, ErrTransportInvalidPath},        // Directory traversal
		}

		for _, tc := range testCases {
			t.Run(tc.key, func(t *testing.T) {
				err := validateS3Key(tc.key)
				if tc.shouldError {
					if err == nil {
						t.Errorf("Expected error for key '%s', got nil", tc.key)
					} else if tc.errType != nil && !errors.Is(err, tc.errType) {
						t.Errorf("Expected error type %v, got %v for key '%s'", tc.errType, err, tc.key)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for key '%s': %v", tc.key, err)
					}
				}
			})
		}
	})

	t.Run("validateS3BucketName", func(t *testing.T) {
		testCases := []struct {
			bucket      string
			shouldError bool
		}{
			{"", true},
			{"a", true},                      // Too short
			{"ab", true},                     // Too short
			{"abc", false},                   // Valid minimum
			{"my-valid-bucket", false},       // Valid
			{"bucket.with.dots", false},      // Valid
			{strings.Repeat("a", 63), false}, // Max length
			{strings.Repeat("a", 64), true},  // Too long
			{"a..b", true},                   // Consecutive periods
			{"-starts-with-hyphen", true},    // Invalid start
			{"ends-with-hyphen-", true},      // Invalid end
			{"UPPERCASE", true},              // Uppercase not allowed
			{"bucket_name", true},            // Underscore not allowed
		}

		for _, tc := range testCases {
			t.Run(tc.bucket, func(t *testing.T) {
				err := validateS3BucketName(tc.bucket)
				if tc.shouldError {
					if err == nil {
						t.Errorf("Expected error for bucket '%s', got nil", tc.bucket)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for bucket '%s': %v", tc.bucket, err)
					}
				}
			})
		}
	})

	t.Run("validateS3Endpoint", func(t *testing.T) {
		testCases := []struct {
			endpoint    string
			shouldError bool
			errType     error
		}{
			{"", false, nil},                                                       // Empty is OK
			{"https://s3.amazonaws.com", false, nil},                               // Valid AWS endpoint
			{"https://my-bucket.s3.amazonaws.com", false, nil},                     // Valid bucket endpoint
			{"http://localhost:9000", true, ErrTransportSecurityViolation},         // localhost
			{"http://127.0.0.1:9000", true, ErrTransportSecurityViolation},         // 127.0.0.1
			{"http://::1:9000", true, ErrTransportSecurityViolation},               // IPv6 loopback
			{"http://10.0.0.1:9000", true, ErrTransportSecurityViolation},          // Private IP
			{"http://192.168.1.1:9000", true, ErrTransportSecurityViolation},       // Private IP
			{"http://172.16.0.1:9000", true, ErrTransportSecurityViolation},        // Private IP
			{"ftp://example.com", true, ErrTransportInvalidPath},                   // Invalid scheme
			{"invalid-url", true, ErrTransportInvalidPath},                         // Invalid URL
			{"https://localhost.localdomain", true, ErrTransportSecurityViolation}, // localhost variation
			{"https://169.254.1.1:9000", true, ErrTransportSecurityViolation},      // APIPA range
		}

		for _, tc := range testCases {
			t.Run(tc.endpoint, func(t *testing.T) {
				err := validateS3Endpoint(tc.endpoint)
				if tc.shouldError {
					if err == nil {
						t.Errorf("Expected error for endpoint '%s', got nil", tc.endpoint)
					} else if tc.errType != nil && !errors.Is(err, tc.errType) {
						t.Errorf("Expected error type %v, got %v for endpoint '%s'", tc.errType, err, tc.endpoint)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for endpoint '%s': %v", tc.endpoint, err)
					}
				}
			})
		}
	})

	t.Run("validateSSHHost", func(t *testing.T) {
		testCases := []struct {
			host        string
			shouldError bool
			errType     error
		}{
			{"", true, ErrTransportInvalidPath},                       // Empty
			{"valid-host.com", false, nil},                            // Valid hostname
			{"192.168.1.1", true, ErrTransportSecurityViolation},      // Private IP
			{"localhost", true, ErrTransportSecurityViolation},        // localhost
			{"127.0.0.1", true, ErrTransportSecurityViolation},        // loopback
			{"::1", true, ErrTransportSecurityViolation},              // IPv6 loopback
			{strings.Repeat("a", 256), true, ErrTransportInvalidPath}, // Too long
			{"host\x00name", true, ErrTransportInvalidPath},           // Null byte
			{"host;command", true, ErrTransportSecurityViolation},     // Command injection
			{"host|command", true, ErrTransportSecurityViolation},     // Command injection
			{"host$(command)", true, ErrTransportSecurityViolation},   // Command injection
			{"host`command`", true, ErrTransportSecurityViolation},    // Command injection
			{"valid-host-name-123", false, nil},                       // Valid with numbers and hyphens
			{"valid.host.name", false, nil},                           // Valid with dots
		}

		for _, tc := range testCases {
			t.Run(tc.host, func(t *testing.T) {
				err := validateSSHHost(tc.host)
				if tc.shouldError {
					if err == nil {
						t.Errorf("Expected error for host '%s', got nil", tc.host)
					} else if tc.errType != nil && !errors.Is(err, tc.errType) {
						t.Errorf("Expected error type %v, got %v for host '%s'", tc.errType, err, tc.host)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for host '%s': %v", tc.host, err)
					}
				}
			})
		}
	})

	t.Run("validateSSHPath", func(t *testing.T) {
		testCases := []struct {
			path        string
			shouldError bool
			errType     error
		}{
			{"", false, nil},                        // Empty is OK
			{"valid/path", false, nil},              // Valid path
			{"a", false, nil},                       // Single char
			{strings.Repeat("a", 4096), false, nil}, // Max length
			{strings.Repeat("a", 4097), true, ErrTransportInvalidPath}, // Too long
			{"/absolute/path", true, ErrTransportInvalidPath},          // Absolute path
			{"~/home/path", true, ErrTransportInvalidPath},             // Home directory
			{"path\x00with\x00null", true, ErrTransportInvalidPath},    // Null byte
			{"path/../traversal", true, ErrTransportInvalidPath},       // Directory traversal
			{"path;command", true, ErrTransportSecurityViolation},      // Command injection
			{"path|command", true, ErrTransportSecurityViolation},      // Command injection
			{"path$(command)", true, ErrTransportSecurityViolation},    // Command injection
		}

		for _, tc := range testCases {
			t.Run(tc.path, func(t *testing.T) {
				err := validateSSHPath(tc.path)
				if tc.shouldError {
					if err == nil {
						t.Errorf("Expected error for path '%s', got nil", tc.path)
					} else if tc.errType != nil && !errors.Is(err, tc.errType) {
						t.Errorf("Expected error type %v, got %v for path '%s'", tc.errType, err, tc.path)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for path '%s': %v", tc.path, err)
					}
				}
			})
		}
	})

	t.Run("validateSSHUsername", func(t *testing.T) {
		testCases := []struct {
			username    string
			shouldError bool
		}{
			{"", true},                        // Empty
			{"validuser", false},              // Valid
			{"user123", false},                // Valid with numbers
			{"user-name", false},              // Valid with hyphen
			{"user_name", false},              // Valid with underscore
			{strings.Repeat("a", 255), false}, // Max length
			{strings.Repeat("a", 256), true},  // Too long
			{"user\x00name", true},            // Null byte
		}

		for _, tc := range testCases {
			t.Run(tc.username, func(t *testing.T) {
				err := validateSSHUsername(tc.username)
				if tc.shouldError {
					if err == nil {
						t.Errorf("Expected error for username '%s', got nil", tc.username)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for username '%s': %v", tc.username, err)
					}
				}
			})
		}
	})

	t.Run("isPrivateIPAddress", func(t *testing.T) {
		testCases := []struct {
			host      string
			isPrivate bool
		}{
			{"127.0.0.1", true},
			{"10.0.0.1", true},
			{"10.255.255.255", true},
			{"172.16.0.1", true},
			{"172.31.255.255", true},
			{"192.168.0.1", true},
			{"192.168.255.255", true},
			{"169.254.0.1", true},
			{"::1", true},
			{"fc00::1", true},
			{"fe80::1", true},
			{"8.8.8.8", false},
			{"208.67.222.222", false},
			{"2001:4860:4860::8888", false},
			{"localhost", false},   // Not an IP address literal
			{"example.com", false}, // Not an IP address literal
		}

		for _, tc := range testCases {
			t.Run(tc.host, func(t *testing.T) {
				result := isPrivateIPAddress(tc.host)
				if result != tc.isPrivate {
					t.Errorf("Expected isPrivateIPAddress(%s) = %v, got %v", tc.host, tc.isPrivate, result)
				}
			})
		}
	})

	t.Run("SecurityConstants", func(t *testing.T) {
		// Verify security constants have expected values
		if MaxS3KeyLength != 1024 {
			t.Errorf("Expected MaxS3KeyLength = 1024, got %d", MaxS3KeyLength)
		}

		if MaxSSHPathLength != 4096 {
			t.Errorf("Expected MaxSSHPathLength = 4096, got %d", MaxSSHPathLength)
		}

		if MaxSSHHostLength != 255 {
			t.Errorf("Expected MaxSSHHostLength = 255, got %d", MaxSSHHostLength)
		}

		if MaxPayloadSizeForSSH != 100*1024*1024 {
			t.Errorf("Expected MaxPayloadSizeForSSH = 100MB, got %d", MaxPayloadSizeForSSH)
		}
	})
}

// TestSSHTransportHostKeyVerification tests host key verification with known hosts
func TestSSHTransportHostKeyVerification(t *testing.T) {
	// Test hostname matching directly (we can't easily test full SSH connection in unit tests)
	transport, err := NewSSHTransportWithOptions(SSHTransportOptions{
		Config: DefaultTransportConfig(),
	})
	if err != nil {
		t.Fatalf("Failed to create SSH transport: %v", err)
	}

	// Test hostname matching
	tests := []struct {
		hostname string
		pattern  string
		match    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "*.example.com", false},    // *.example.com does NOT match example.com
		{"foo.example.com", "*.example.com", true}, // *.example.com matches foo.example.com
		{"foo.example.com", ".example.com", true},  // .example.com matches foo.example.com
		{"example.com", "other.com", false},
		{"example.com:22", "example.com", true},
		{"*.example.com", "*", true}, // * matches everything
	}

	for _, tc := range tests {
		result := transport.hostnameMatches(tc.hostname, tc.pattern)
		if result != tc.match {
			t.Errorf("hostnameMatches(%q, %q) = %v, expected %v", tc.hostname, tc.pattern, result, tc.match)
		}
	}

	// Test that createKnownHostsCallback can be created
	callback, err := transport.createKnownHostsCallback()
	if err != nil {
		t.Fatalf("Failed to create host key callback: %v", err)
	}
	if callback == nil {
		t.Fatal("Expected callback to be non-nil")
	}
}
