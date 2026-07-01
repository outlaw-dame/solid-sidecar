// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Rate Limiter Tests
// =============================================================================

func TestRateLimiter_Allow(t *testing.T) {
	limiter := NewRateLimiter(5, 1*time.Second)

	// Should allow first 5 requests
	for i := 0; i < 5; i++ {
		if !limiter.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	if limiter.Allow() {
		t.Error("6th request should be denied")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	limiter := NewRateLimiter(2, 1*time.Second)

	// Use up the limit
	limiter.Allow()
	limiter.Allow()

	// Should be denied
	if limiter.Allow() {
		t.Error("Request should be denied after limit reached")
	}

	// Reset
	limiter.Reset()

	// Should be allowed again
	if !limiter.Allow() {
		t.Error("Request should be allowed after reset")
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	limiter := NewRateLimiter(2, 50*time.Millisecond)

	// Use up the limit
	limiter.Allow()
	limiter.Allow()

	// Should be denied
	if limiter.Allow() {
		t.Error("Request should be denied")
	}

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again
	if !limiter.Allow() {
		t.Error("Request should be allowed after window expiry")
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	limiter := NewRateLimiter(10, 1*time.Second)

	// Run 20 concurrent requests
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func() {
			limiter.Allow()
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 20; i++ {
		<-done
	}

	// The limiter should still be functional
	limiter.Reset()
	if !limiter.Allow() {
		t.Error("Limiter should be functional after concurrent access")
	}
}

// =============================================================================
// ID Sanitization Tests
// =============================================================================

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{
			name:    "valid IRI with path",
			id:      "http://example.com/app1",
			wantErr: false,
		},
		{
			name:    "valid IRI without path",
			id:      "http://example.com",
			wantErr: false,
		},
		{
			name:    "empty ID",
			id:      "",
			wantErr: true,
		},
		{
			name:    "path traversal with ..",
			id:      "http://example.com/../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "path traversal with backslash",
			id:      "foo\\bar",
			wantErr: true,
		},
		{
			name:    "ID too long",
			id:      string(bytes.Repeat([]byte("a"), 2049)),
			wantErr: true,
		},
		{
			name:    "max length ID",
			id:      string(bytes.Repeat([]byte("a"), 2048)),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sanitizeID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeWebID(t *testing.T) {
	tests := []struct {
		name    string
		webID   string
		wantErr bool
	}{
		{
			name:    "valid WebID with fragment",
			webID:   "https://example.com/profile/card#me",
			wantErr: false,
		},
		{
			name:    "empty WebID",
			webID:   "",
			wantErr: true,
		},
		{
			name:    "WebID without fragment",
			webID:   "https://example.com/profile/card",
			wantErr: true,
		},
		{
			name:    "WebID without scheme",
			webID:   "example.com/profile/card#me",
			wantErr: true,
		},
		{
			name:    "WebID too long",
			webID:   "https://example.com/" + string(bytes.Repeat([]byte("a"), 2000)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sanitizeWebID(tt.webID)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeWebID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Request Validation Tests
// =============================================================================

func TestValidateContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{
			name:        "application/json",
			contentType: "application/json",
			wantErr:     false,
		},
		{
			name:        "application/json; charset=utf-8",
			contentType: "application/json; charset=utf-8",
			wantErr:     false,
		},
		{
			name:        "application/ld+json",
			contentType: "application/ld+json",
			wantErr:     false,
		},
		{
			name:        "empty content type",
			contentType: "",
			wantErr:     true,
		},
		{
			name:        "text/html",
			contentType: "text/html",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Content-Type", tt.contentType)

			err := validateContentType(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateContentType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLimitBodySize(t *testing.T) {
	// Create a request with a body
	body := "test body"
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))

	// Limit to 100 bytes
	limited, err := limitBodySize(req, 100)
	if err != nil {
		t.Fatalf("limitBodySize() error = %v", err)
	}

	// Read from limited body
	result, err := io.ReadAll(limited)
	if err != nil {
		t.Fatalf("failed to read from limited body: %v", err)
	}

	if string(result) != body {
		t.Errorf("body mismatch: got %q, want %q", string(result), body)
	}

	// Close the limited body
	if err := limited.Close(); err != nil {
		t.Errorf("failed to close limited body: %v", err)
	}
}

// =============================================================================
// Security Headers Tests
// =============================================================================

func TestSecurityHeaders(t *testing.T) {
	handler := withSAISecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Check that security headers are present
	expectedHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	for _, header := range expectedHeaders {
		if rec.Header().Get(header) == "" {
			t.Errorf("Missing security header: %s", header)
		}
	}
}

// =============================================================================
// Rate Limiting Middleware Tests
// =============================================================================

func TestWithSAIRateLimiting(t *testing.T) {
	limiter := NewRateLimiter(2, 1*time.Second)

	handler := withSAIRateLimiting(limiter, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected status %d, got %d", i+1, http.StatusOK, rec.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected rate limit status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}
}

// =============================================================================
// Resource Validation Middleware Tests
// =============================================================================

func TestWithSAIResourceValidation(t *testing.T) {
	// Test valid ID - directly test sanitizeID
	if err := sanitizeID("http://example.com/app1"); err != nil {
		t.Errorf("Expected no error for valid IRI, got: %v", err)
	}

	// Test invalid ID with path traversal (using ..)
	if err := sanitizeID("../etc/passwd"); err == nil {
		t.Error("Expected error for ID with .., got nil")
	}

	// Test invalid ID with backslash
	if err := sanitizeID("foo\\bar"); err == nil {
		t.Error("Expected error for ID with backslash, got nil")
	}
}

// =============================================================================
// Retry Logic Tests
// =============================================================================

func TestCalculateDelay(t *testing.T) {
	config := RetryConfig{
		MaxRetries:        5,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          1 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            false,
	}

	// First delay: 100ms * 2 = 200ms
	delay1 := calculateDelay(100*time.Millisecond, config)
	if delay1 != 200*time.Millisecond {
		t.Errorf("Expected 200ms, got %v", delay1)
	}

	// Second delay: 200ms * 2 = 400ms
	delay2 := calculateDelay(200*time.Millisecond, config)
	if delay2 != 400*time.Millisecond {
		t.Errorf("Expected 400ms, got %v", delay2)
	}

	// Third delay: 400ms * 2 = 800ms
	delay3 := calculateDelay(400*time.Millisecond, config)
	if delay3 != 800*time.Millisecond {
		t.Errorf("Expected 800ms, got %v", delay3)
	}

	// Fourth delay: 800ms * 2 = 1600ms, but capped at 1s
	delay4 := calculateDelay(800*time.Millisecond, config)
	if delay4 != 1*time.Second {
		t.Errorf("Expected 1s (capped), got %v", delay4)
	}
}

func TestApplyJitter(t *testing.T) {
	// Seed the random number generator for reproducibility
	// Note: In real tests, you might want to use a fixed seed
	delay := 100 * time.Millisecond

	// Run multiple times and verify the jitter is applied
	for i := 0; i < 100; i++ {
		jittered := applyJitter(delay)

		// Jitter should be between 50ms and 100ms
		if jittered < 50*time.Millisecond || jittered > 100*time.Millisecond {
			t.Errorf("Jittered delay %v is out of expected range [50ms, 100ms]", jittered)
		}
	}
}

func TestWithRetry(t *testing.T) {
	config := RetryConfig{
		MaxRetries:        3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		Jitter:            false,
	}

	// Test successful operation on first try
	attempts, err := WithRetry(context.Background(), config, func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("Expected 1 attempt, got %d", attempts)
	}

	// Test successful operation on second try
	tryCount := 0
	attempts, err = WithRetry(context.Background(), config, func() error {
		tryCount++
		if tryCount < 2 {
			return errors.New("temporary error")
		}
		return nil
	})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", attempts)
	}

	// Test failure after all retries
	attempts, err = WithRetry(context.Background(), config, func() error {
		return errors.New("persistent error")
	})
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if attempts != 4 { // 1 initial + 3 retries
		t.Errorf("Expected 4 attempts, got %d", attempts)
	}
}

func TestWithRetry_ContextCancellation(t *testing.T) {
	config := RetryConfig{
		MaxRetries:        10,
		InitialDelay:      1 * time.Second,
		MaxDelay:          10 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	attempts, err := WithRetry(ctx, config, func() error {
		return errors.New("error")
	})

	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got %v", err)
	}

	// Should have made at least 1 attempt before context timeout
	if attempts < 1 {
		t.Errorf("Expected at least 1 attempt, got %d", attempts)
	}
}

// =============================================================================
// Error Writing Tests
// =============================================================================

func TestWriteSAIError(t *testing.T) {
	rec := httptest.NewRecorder()

	writeSAIError(rec, http.StatusBadRequest, SAIError{
		Code:    ErrCodeInvalidRequest,
		Message: "test error",
	})

	// Check status code
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	// Check content type
	if rec.Header().Get("Content-Type") != ContentTypeSAIApplicationJSON {
		t.Errorf("Expected Content-Type %s, got %s", ContentTypeSAIApplicationJSON, rec.Header().Get("Content-Type"))
	}

	// Check security headers are present
	if rec.Header().Get("X-Content-Type-Options") == "" {
		t.Error("Missing X-Content-Type-Options header")
	}

	// Check body
	body := rec.Body.String()
	if !bytes.Contains([]byte(body), []byte(`"code":"sai_invalid_request"`)) {
		t.Errorf("Expected error code in body, got: %s", body)
	}
}

// =============================================================================
// Default Authenticator Tests
// =============================================================================

func TestDefaultAuthenticator_Authenticate_MissingHeader(t *testing.T) {
	auth := NewDefaultAuthenticator(nil)

	req := httptest.NewRequest("GET", "/", nil)
	_, err := auth.Authenticate(req)

	if err == nil {
		t.Error("Expected error for missing Authorization header")
	}
}

func TestDefaultAuthenticator_Authenticate_InvalidFormat(t *testing.T) {
	auth := NewDefaultAuthenticator(nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "InvalidFormat")

	_, err := auth.Authenticate(req)

	if err == nil {
		t.Error("Expected error for invalid Authorization header format")
	}
}

func TestDefaultAuthenticator_Authenticate_NotIntegrated(t *testing.T) {
	auth := NewDefaultAuthenticator(nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	_, err := auth.Authenticate(req)

	// Should return error indicating integration is needed
	if err == nil {
		t.Error("Expected error indicating authn not integrated")
	}
	if !strings.Contains(err.Error(), "not yet integrated") {
		t.Errorf("Expected error about integration, got: %v", err)
	}
}

func TestDefaultAuthenticator_Authorize(t *testing.T) {
	auth := NewDefaultAuthenticator(nil)

	// Should deny all access until implemented
	err := auth.Authorize("user1", "resource1", "read")

	if err == nil {
		t.Error("Expected error for authorization not implemented")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("Expected error about implementation, got: %v", err)
	}
}
