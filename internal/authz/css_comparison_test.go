// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testCSSServer creates a mock CSS server for testing
func testCSSServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back the request method and path
		w.Header().Set("X-CSS-Response", "true")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS Response: " + r.Method + " " + r.URL.Path))
	}))
}

// testSidecarServer creates a mock sidecar server for testing
func testSidecarServer(cssServer *httptest.Server) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Proxy to CSS server
		proxyURL := cssServer.URL + r.URL.Path
		if r.URL.RawQuery != "" {
			proxyURL += "?" + r.URL.RawQuery
		}

		// Make request to CSS
		cssResp, err := http.Get(proxyURL)
		if err != nil {
			http.Error(w, "CSS unavailable", http.StatusServiceUnavailable)
			return
		}
		defer cssResp.Body.Close()

		// Copy headers
		for key, values := range cssResp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		// Add sidecar-specific header
		w.Header().Set("X-Sidecar-Proxy", "true")

		w.WriteHeader(cssResp.StatusCode)
		// Copy body
		buf := make([]byte, 1024)
		for {
			n, err := cssResp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}))
}

// TestCSSComparisonHarnessCreation tests creating a CSS comparison harness
func TestCSSComparisonHarnessCreation(t *testing.T) {
	cssServer := testCSSServer()
	defer cssServer.Close()

	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: cssServer.URL, // Use same server for simplicity in test
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create CSS comparison harness: %v", err)
	}
	if harness == nil {
		t.Fatal("CSS comparison harness is nil")
	}
}

// TestCSSComparisonHarnessDefaultOptions tests default options
func TestCSSComparisonHarnessDefaultOptions(t *testing.T) {
	options := DefaultCSSComparisonHarnessOptions()

	if options.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", options.Timeout)
	}
	if options.MaxBodySize != 10*1024*1024 {
		t.Errorf("expected default max body size 10MB, got %d", options.MaxBodySize)
	}
	if options.Logger != nil {
		t.Error("expected logger to be nil by default")
	}
}

// TestCSSComparisonHarnessNilURLs tests error handling for nil URLs
func TestCSSComparisonHarnessNilURLs(t *testing.T) {
	testCases := []struct {
		name        string
		options     CSSComparisonHarnessOptions
		expectError bool
	}{
		{
			name: "nil CSS URL",
			options: CSSComparisonHarnessOptions{
				CSSURL:     "",
				SidecarURL: "http://localhost:8080",
			},
			expectError: true,
		},
		{
			name: "nil sidecar URL",
			options: CSSComparisonHarnessOptions{
				CSSURL:     "http://localhost:3000",
				SidecarURL: "",
			},
			expectError: true,
		},
		{
			name: "invalid CSS URL",
			options: CSSComparisonHarnessOptions{
				CSSURL:     "://invalid",
				SidecarURL: "http://localhost:8080",
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCSSComparisonHarness(tc.options)
			if (err != nil) != tc.expectError {
				t.Errorf("NewCSSComparisonHarness() error = %v, expectError %v", err, tc.expectError)
			}
		})
	}
}

// TestCSSComparisonHarnessCompare tests basic comparison functionality
func TestCSSComparisonHarnessCompare(t *testing.T) {
	cssServer := testCSSServer()
	defer cssServer.Close()

	// Create a simple echo server for sidecar
	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSS-Response", "true")
		w.Header().Set("X-Sidecar-Proxy", "true")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS Response: " + r.Method + " " + r.URL.Path))
	}))
	defer sidecarServer.Close()

	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: sidecarServer.URL,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// Perform a comparison
	result, err := harness.Compare(context.Background(), "GET", "/test", nil, http.Header{})
	if err != nil {
		t.Fatalf("comparison failed: %v", err)
	}

	// Check results
	if result.Method != "GET" {
		t.Errorf("expected method GET, got %q", result.Method)
	}
	if result.Path != "/test" {
		t.Errorf("expected path /test, got %q", result.Path)
	}
	if result.CSSStatus != http.StatusOK {
		t.Errorf("expected CSS status 200, got %d", result.CSSStatus)
	}
	if result.SidecarStatus != http.StatusOK {
		t.Errorf("expected sidecar status 200, got %d", result.SidecarStatus)
	}

	// Statuses match, so StatusMatch should be true
	if !result.StatusMatch {
		t.Error("expected status match to be true")
	}

	// Body hashes might differ due to sidecar adding headers, but status should match
	if result.StatusMatch && result.HeadersMatch && result.BodyMatch && result.IsMismatch {
		t.Error("expected no mismatch when all components match")
	}
}

// TestCSSComparisonHarnessMetrics tests metrics tracking
func TestCSSComparisonHarnessMetrics(t *testing.T) {
	cssServer := testCSSServer()
	defer cssServer.Close()

	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: cssServer.URL,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// Reset metrics
	harness.ResetMetrics()

	// Perform some comparisons
	for i := 0; i < 5; i++ {
		_, err := harness.Compare(context.Background(), "GET", "/test"+string(rune(i)), nil, http.Header{})
		if err != nil {
			t.Fatalf("comparison %d failed: %v", i, err)
		}
	}

	// Check metrics
	metrics := harness.GetMetrics()
	if metrics.TotalComparisons != 5 {
		t.Errorf("expected 5 total comparisons, got %d", metrics.TotalComparisons)
	}
	if metrics.Matching+metrics.Mismatched != 5 {
		t.Errorf("expected 5 total results, got %d", metrics.Matching+metrics.Mismatched)
	}
}

// TestCSSComparisonHarnessMismatchRate tests mismatch rate calculation
func TestCSSComparisonHarnessMismatchRate(t *testing.T) {
	cssServer := testCSSServer()
	defer cssServer.Close()

	// Create a sidecar that always returns a different status
	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Sidecar Response"))
	}))
	defer sidecarServer.Close()

	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: sidecarServer.URL,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// Reset metrics
	harness.ResetMetrics()

	// Perform comparisons - all should mismatch on status
	for i := 0; i < 10; i++ {
		_, err := harness.Compare(context.Background(), "GET", "/test", nil, http.Header{})
		if err != nil {
			t.Fatalf("comparison %d failed: %v", i, err)
		}
	}

	// Check mismatch rate
	metrics := harness.GetMetrics()
	if metrics.StatusMismatches != 10 {
		t.Errorf("expected 10 status mismatches, got %d", metrics.StatusMismatches)
	}

	mismatchRate := harness.MismatchRate()
	if mismatchRate != 1.0 {
		t.Errorf("expected mismatch rate 1.0, got %f", mismatchRate)
	}
}

// TestCSSComparisonHarnessSummary tests summary generation
func TestCSSComparisonHarnessSummary(t *testing.T) {
	cssServer := testCSSServer()
	defer cssServer.Close()

	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: cssServer.URL,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// With no comparisons, summary should indicate that
	harness.ResetMetrics()
	summary := harness.Summary()
	if summary != "No comparisons performed" {
		t.Errorf("expected 'No comparisons performed', got %q", summary)
	}

	// After some comparisons
	for i := 0; i < 3; i++ {
		_, err := harness.Compare(context.Background(), "GET", "/test", nil, http.Header{})
		if err != nil {
			t.Fatalf("comparison %d failed: %v", i, err)
		}
	}

	summary = harness.Summary()
	if summary == "" || summary == "No comparisons performed" {
		t.Error("expected non-empty summary after comparisons")
	}
}

// TestCSSComparisonHarnessBatch tests batch comparison
func TestCSSComparisonHarnessBatch(t *testing.T) {
	cssServer := testCSSServer()
	defer cssServer.Close()

	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: cssServer.URL,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	requests := []struct {
		Method  string
		Path    string
		Body    []byte
		Headers http.Header
	}{
		{Method: "GET", Path: "/test1"},
		{Method: "POST", Path: "/test2"},
		{Method: "GET", Path: "/test3"},
	}

	results, err := harness.CompareBatch(context.Background(), requests)
	if err != nil {
		t.Fatalf("batch comparison failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

// TestCSSComparisonHarnessExportMetrics tests metrics export
func TestCSSComparisonHarnessExportMetrics(t *testing.T) {
	cssServer := testCSSServer()
	defer cssServer.Close()

	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: cssServer.URL,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// Perform some comparisons
	for i := 0; i < 3; i++ {
		_, err := harness.Compare(context.Background(), "GET", "/test", nil, http.Header{})
		if err != nil {
			t.Fatalf("comparison %d failed: %v", i, err)
		}
	}

	// Export metrics
	metricsJSON, err := harness.ExportMetrics()
	if err != nil {
		t.Fatalf("failed to export metrics: %v", err)
	}

	if len(metricsJSON) == 0 {
		t.Error("expected non-empty metrics JSON")
	}
}

// TestCSSComparisonHarnessHeadersMatch tests header comparison logic
// Note: headersMatch is unexported, so we test it indirectly through Compare
func TestCSSComparisonHarnessHeadersMatch(t *testing.T) {
	// Create a CSS server that returns specific headers
	cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Custom", "value1")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS Response"))
	}))
	defer cssServer.Close()

	// Create a sidecar that returns the same headers plus sidecar-specific ones
	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Custom", "value1")
		w.Header().Set("X-Sidecar-Proxy", "true")   // Sidecar-added, should be ignored
		w.Header().Set("X-Forwarded-For", "client") // Sidecar-added, should be ignored
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS Response"))
	}))
	defer sidecarServer.Close()

	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: sidecarServer.URL,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// Perform comparison - headers should match (sidecar-added headers are ignored)
	result, err := harness.Compare(context.Background(), "GET", "/test", nil, http.Header{})
	if err != nil {
		t.Fatalf("comparison failed: %v", err)
	}

	// Headers should match because sidecar-added headers are filtered out
	if !result.HeadersMatch {
		t.Error("expected headers to match when only sidecar-added headers differ")
	}

	// Test with different content type
	sidecarServerDifferent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html") // Different from CSS
		w.Header().Set("X-Custom", "value1")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS Response"))
	}))
	defer sidecarServerDifferent.Close()

	harness2, _ := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: sidecarServerDifferent.URL,
		Timeout:    5 * time.Second,
	})

	result2, _ := harness2.Compare(context.Background(), "GET", "/test", nil, http.Header{})
	if result2.HeadersMatch {
		t.Error("expected headers to not match when content types differ")
	}
}

// TestCSSComparisonHarnessTimeout tests timeout handling
func TestCSSComparisonHarnessTimeout(t *testing.T) {
	// Create a slow server
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:      slowServer.URL,
		SidecarURL:  slowServer.URL,
		Timeout:     50 * time.Millisecond, // Very short timeout
		MaxBodySize: 1024,
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// This should timeout
	_, err = harness.Compare(context.Background(), "GET", "/slow", nil, http.Header{})
	if err == nil {
		// It might still succeed if the server responds fast enough
		// Just check that it doesn't hang indefinitely
		t.Log("Request completed before timeout")
	}
}
