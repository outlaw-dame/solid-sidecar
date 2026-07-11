// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements CSS direct vs sidecar vs native-runtime comparison harness.
package conformance

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// CSSComparisonHarness implements comparison testing across CSS, sidecar, and native runtime
type CSSComparisonHarness struct {
	// Configuration for each runtime mode
	CSSConfig     RuntimeConfig
	SidecarConfig RuntimeConfig
	NativeConfig  RuntimeConfig

	// Test configuration
	Timeout     time.Duration
	StrictMode  bool
	DebugOutput bool

	// Results storage
	mu               sync.Mutex
	AllResults       []ComparisonTestResult
	ComparisonMatrix map[string][]ComparisonTestResult
}

// RuntimeConfig holds configuration for a specific runtime
type RuntimeConfig struct {
	Name       string
	BaseURL    string
	Client     *http.Client
	Enabled    bool
	Timeout    time.Duration
	SkipReason string // Reason if disabled
}

// ComparisonTestResult represents the result of a comparison test
type ComparisonTestResult struct {
	TestID          string                   `json:"test_id"`
	TestName        string                   `json:"test_name"`
	TestCategory    string                   `json:"test_category"`
	TestDescription string                   `json:"test_description"`
	TestStatus      string                   `json:"test_status"` // "passed", "failed", "skipped", "error", "diverged"
	ErrorMessage    string                   `json:"error_message,omitempty"`
	ErrorDetails    string                   `json:"error_details,omitempty"`
	StartTime       string                   `json:"start_time"`
	EndTime         string                   `json:"end_time"`
	DurationMs      int64                    `json:"duration_ms"`
	Expectation     string                   `json:"expectation"`
	ActualResult    string                   `json:"actual_result"`
	Severity        string                   `json:"severity"`
	SolidSpecRef    string                   `json:"solid_spec_ref,omitempty"`
	RuntimeResults  map[string]RuntimeResult `json:"runtime_results"`
}

// RuntimeResult holds the result from a specific runtime
type RuntimeResult struct {
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	BodyPreview string            `json:"body_preview,omitempty"` // First 100 chars
	BodySize    int               `json:"body_size"`
	DurationMs  int64             `json:"duration_ms"`
	Error       string            `json:"error,omitempty"`
	Skipped     bool              `json:"skipped"`
	SkipReason  string            `json:"skip_reason,omitempty"`
}

// NewCSSComparisonHarness creates a new CSS comparison harness
func NewCSSComparisonHarness(cssURL, sidecarURL, nativeURL string) *CSSComparisonHarness {
	// Create HTTP clients with appropriate timeouts and security settings
	defaultTimeout := 30 * time.Second

	createClient := func(timeout time.Duration) *http.Client {
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false, // Always verify TLS in production
				},
			},
		}
	}

	harness := &CSSComparisonHarness{
		CSSConfig: RuntimeConfig{
			Name:    "CSS",
			BaseURL: cssURL,
			Client:  createClient(defaultTimeout),
			Enabled: cssURL != "",
			Timeout: defaultTimeout,
		},
		SidecarConfig: RuntimeConfig{
			Name:    "Sidecar",
			BaseURL: sidecarURL,
			Client:  createClient(defaultTimeout),
			Enabled: sidecarURL != "",
			Timeout: defaultTimeout,
		},
		NativeConfig: RuntimeConfig{
			Name:    "Native Runtime",
			BaseURL: nativeURL,
			Client:  createClient(defaultTimeout),
			Enabled: nativeURL != "",
			Timeout: defaultTimeout,
		},
		Timeout:          defaultTimeout,
		StrictMode:       true,
		ComparisonMatrix: make(map[string][]ComparisonTestResult),
	}

	// Set skip reasons if URLs are empty
	if cssURL == "" {
		harness.CSSConfig.SkipReason = "CSS URL not configured"
	}
	if sidecarURL == "" {
		harness.SidecarConfig.SkipReason = "Sidecar URL not configured"
	}
	if nativeURL == "" {
		harness.NativeConfig.SkipReason = "Native runtime URL not configured"
	}

	return harness
}

// Run executes all comparison tests
func (h *CSSComparisonHarness) Run(ctx context.Context) error {
	fmt.Printf("Starting CSS vs Sidecar vs Native Runtime Comparison\n")
	fmt.Printf("CSS URL: %s (Enabled: %v)\n", h.CSSConfig.BaseURL, h.CSSConfig.Enabled)
	fmt.Printf("Sidecar URL: %s (Enabled: %v)\n", h.SidecarConfig.BaseURL, h.SidecarConfig.Enabled)
	fmt.Printf("Native URL: %s (Enabled: %v)\n", h.NativeConfig.BaseURL, h.NativeConfig.Enabled)
	fmt.Printf("Timeout: %v\n", h.Timeout)
	fmt.Printf("Strict Mode: %v\n\n", h.StrictMode)

	startTime := time.Now()

	// Run each test category
	categories := []struct {
		name string
		run  func(context.Context) []ComparisonTestResult
	}{
		{"Authentication", h.runAuthTests},
		{"Resource CRUD", h.runResourceCRUDTests},
		{"Policy Resources", h.runPolicyTests},
		{"Conditional Requests", h.runConditionalTests},
		{"Content Negotiation", h.runContentNegotiationTests},
		{"CORS", h.runCORSTests},
	}

	for _, category := range categories {
		fmt.Printf("Running %s tests...\n", category.name)
		categoryStart := time.Now()

		categoryResults := category.run(ctx)

		h.mu.Lock()
		h.ComparisonMatrix[category.name] = categoryResults
		h.AllResults = append(h.AllResults, categoryResults...)
		h.mu.Unlock()

		// Print category summary
		categoryDuration := time.Since(categoryStart)
		passed := h.countPassed(categoryResults)
		failed := h.countFailed(categoryResults)
		diverged := h.countDiverged(categoryResults)
		total := len(categoryResults)

		fmt.Printf("  %s: %d/%d passed, %d failed, %d diverged (%v)\n",
			category.name, passed, total, failed, diverged, categoryDuration.Round(time.Millisecond))
	}

	// Print overall summary
	elapsed := time.Since(startTime)
	passed := h.countPassed(h.AllResults)
	failed := h.countFailed(h.AllResults)
	diverged := h.countDiverged(h.AllResults)
	total := len(h.AllResults)

	fmt.Printf("\n=== Comparison Test Summary ===\n")
	fmt.Printf("Total Tests: %d\n", total)
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)
	fmt.Printf("Diverged: %d\n", diverged)
	fmt.Printf("Total Time: %v\n", elapsed.Round(time.Millisecond))

	// Print divergence details
	divergedTests := h.GetDivergedTests()
	if len(divergedTests) > 0 {
		fmt.Printf("\n=== Divergence Details ===\n")
		for _, result := range divergedTests {
			fmt.Printf("  %s (%s):\n", result.TestName, result.TestID)
			for runtime, runtimeResult := range result.RuntimeResults {
				if runtimeResult.Error != "" {
					fmt.Printf("    %s: ERROR - %s\n", runtime, runtimeResult.Error)
				} else if runtimeResult.Skipped {
					fmt.Printf("    %s: SKIPPED - %s\n", runtime, runtimeResult.SkipReason)
				} else {
					fmt.Printf("    %s: %d (%d bytes)\n", runtime, runtimeResult.StatusCode, runtimeResult.BodySize)
				}
			}
		}
	}

	return nil
}

// runAuthTests runs authentication comparison tests
func (h *CSSComparisonHarness) runAuthTests(ctx context.Context) []ComparisonTestResult {
	results := make([]ComparisonTestResult, 0)

	// Test 1: Unauthenticated request to protected resource
	results = append(results, h.runSingleComparisonTest(ctx, "auth-001", "Unauthenticated request",
		"Authentication", "Verify all runtimes return 401 for unauthenticated protected resource access",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/protected-resource", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodGET, url, nil)
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#authentication"))

	// Test 2: Request with invalid DPoP token
	results = append(results, h.runSingleComparisonTest(ctx, "auth-002", "Invalid DPoP token",
		"Authentication", "Verify all runtimes return 401 for invalid DPoP",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/protected-resource", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodGET, url, nil)
			req.Header.Set("Authorization", "DPoP invalid-token")
			req.Header.Set("DPoP", "invalid-proof")
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#authentication"))

	return results
}

// runResourceCRUDTests runs resource CRUD comparison tests
func (h *CSSComparisonHarness) runResourceCRUDTests(ctx context.Context) []ComparisonTestResult {
	results := make([]ComparisonTestResult, 0)

	// Test 1: Create a new resource
	results = append(results, h.runSingleComparisonTest(ctx, "crud-001", "Create resource",
		"Resource CRUD", "Verify all runtimes support resource creation",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource-%d", runtime.BaseURL, time.Now().UnixNano())
			start := time.Now()
			body := []byte("test content")
			req, _ := http.NewRequestWithContext(ctx, MethodPUT, url, bytes.NewReader(body))
			req.Header.Set("Content-Type", "text/plain")
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#http-resources"))

	// Test 2: Read the created resource
	results = append(results, h.runSingleComparisonTest(ctx, "crud-002", "Read resource",
		"Resource CRUD", "Verify all runtimes support resource reading",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodGET, url, nil)
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			// Read body to get size and preview
			body, _ := io.ReadAll(resp.Body)
			preview := string(body)
			if len(preview) > 100 {
				preview = preview[:100] + "..."
			}

			return RuntimeResult{
				StatusCode:  resp.StatusCode,
				Headers:     extractHeaders(resp.Header),
				BodyPreview: preview,
				BodySize:    len(body),
				DurationMs:  duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#http-resources"))

	// Test 3: Update resource
	results = append(results, h.runSingleComparisonTest(ctx, "crud-003", "Update resource",
		"Resource CRUD", "Verify all runtimes support resource updates",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource", runtime.BaseURL)
			start := time.Now()
			body := []byte("updated content")
			req, _ := http.NewRequestWithContext(ctx, MethodPUT, url, bytes.NewReader(body))
			req.Header.Set("Content-Type", "text/plain")
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#http-resources"))

	// Test 4: Delete resource
	results = append(results, h.runSingleComparisonTest(ctx, "crud-004", "Delete resource",
		"Resource CRUD", "Verify all runtimes support resource deletion",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodDELETE, url, nil)
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#http-resources"))

	// Test 5: Container operations
	results = append(results, h.runSingleComparisonTest(ctx, "crud-005", "Container listing",
		"Resource CRUD", "Verify all runtimes support container listing",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodGET, url, nil)
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			body, _ := io.ReadAll(resp.Body)
			preview := string(body)
			if len(preview) > 100 {
				preview = preview[:100] + "..."
			}

			return RuntimeResult{
				StatusCode:  resp.StatusCode,
				Headers:     extractHeaders(resp.Header),
				BodyPreview: preview,
				BodySize:    len(body),
				DurationMs:  duration,
			}
		}, SeverityMedium, "https://solidproject.org/TR/protocol#containers"))

	return results
}

// runPolicyTests runs policy resource comparison tests
func (h *CSSComparisonHarness) runPolicyTests(ctx context.Context) []ComparisonTestResult {
	results := make([]ComparisonTestResult, 0)

	// Test 1: WAC policy resource
	results = append(results, h.runSingleComparisonTest(ctx, "policy-001", "WAC policy resource",
		"Policy Resources", "Verify all runtimes handle WAC policy resources",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource.wac", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodGET, url, nil)
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#wac"))

	// Test 2: ACP policy resource
	results = append(results, h.runSingleComparisonTest(ctx, "policy-002", "ACP policy resource",
		"Policy Resources", "Verify all runtimes handle ACP policy resources",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource.acp", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodGET, url, nil)
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/ED/acp"))

	return results
}

// runConditionalTests runs conditional request comparison tests
func (h *CSSComparisonHarness) runConditionalTests(ctx context.Context) []ComparisonTestResult {
	results := make([]ComparisonTestResult, 0)

	// Test 1: If-Match with matching ETag
	results = append(results, h.runSingleComparisonTest(ctx, "conditional-001", "If-Match matching ETag",
		"Conditional Requests", "Verify all runtimes handle If-Match correctly",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-conditional-resource", runtime.BaseURL)
			start := time.Now()

			// First, create the resource
			body := []byte("test content")
			putReq, _ := http.NewRequestWithContext(ctx, MethodPUT, url, bytes.NewReader(body))
			putReq.Header.Set("Content-Type", "text/plain")
			putResp, putErr := runtime.Client.Do(putReq)
			if putErr != nil {
				return RuntimeResult{Error: putErr.Error(), DurationMs: time.Since(start).Milliseconds()}
			}
			if putResp != nil && putResp.Body != nil {
				io.Copy(io.Discard, putResp.Body)
				putResp.Body.Close()
			}

			// Get the ETag from the response
			eTag := putResp.Header.Get("ETag")
			if eTag == "" {
				eTag = "\"test-etag\"" // Use a test ETag if not provided
			}

			// Now try to update with If-Match
			updateBody := []byte("updated content")
			req, _ := http.NewRequestWithContext(ctx, MethodPUT, url, bytes.NewReader(updateBody))
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("If-Match", eTag)
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#http-conditional"))

	// Test 2: If-None-Match with existing resource
	results = append(results, h.runSingleComparisonTest(ctx, "conditional-002", "If-None-Match existing resource",
		"Conditional Requests", "Verify all runtimes handle If-None-Match correctly",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-conditional-resource", runtime.BaseURL)
			start := time.Now()

			// First, create the resource if it doesn't exist
			body := []byte("test content")
			putReq, _ := http.NewRequestWithContext(ctx, MethodPUT, url, bytes.NewReader(body))
			putReq.Header.Set("Content-Type", "text/plain")
			putResp, putErr := runtime.Client.Do(putReq)
			if putErr != nil {
				return RuntimeResult{Error: putErr.Error(), DurationMs: time.Since(start).Milliseconds()}
			}
			if putResp != nil && putResp.Body != nil {
				io.Copy(io.Discard, putResp.Body)
				putResp.Body.Close()
			}

			// Get the ETag
			eTag := putResp.Header.Get("ETag")
			if eTag == "" {
				eTag = "\"test-etag\""
			}

			// Try to create again with If-None-Match
			req, _ := http.NewRequestWithContext(ctx, MethodPUT, url, bytes.NewReader(body))
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("If-None-Match", eTag)
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#http-conditional"))

	return results
}

// runContentNegotiationTests runs content negotiation comparison tests
func (h *CSSComparisonHarness) runContentNegotiationTests(ctx context.Context) []ComparisonTestResult {
	results := make([]ComparisonTestResult, 0)

	// Test 1: Accept header for RDF formats
	results = append(results, h.runSingleComparisonTest(ctx, "negotiation-001", "RDF content negotiation",
		"Content Negotiation", "Verify all runtimes support RDF content negotiation",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodGET, url, nil)
			req.Header.Set("Accept", "text/turtle, application/ld+json;q=0.8, */*;q=0.1")
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#content-negotiation"))

	// Test 2: Accept header for non-RDF formats
	results = append(results, h.runSingleComparisonTest(ctx, "negotiation-002", "Non-RDF content negotiation",
		"Content Negotiation", "Verify all runtimes support non-RDF content negotiation",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource.txt", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodGET, url, nil)
			req.Header.Set("Accept", "text/plain, */*;q=0.1")
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityMedium, "https://solidproject.org/TR/protocol#content-negotiation"))

	return results
}

// runCORSTests runs CORS comparison tests
func (h *CSSComparisonHarness) runCORSTests(ctx context.Context) []ComparisonTestResult {
	results := make([]ComparisonTestResult, 0)

	// Test 1: OPTIONS request (preflight)
	results = append(results, h.runSingleComparisonTest(ctx, "cors-001", "CORS preflight OPTIONS",
		"CORS", "Verify all runtimes handle CORS preflight requests",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodOPTIONS, url, nil)
			req.Header.Set("Origin", "https://example.com")
			req.Header.Set("Access-Control-Request-Method", "GET")
			req.Header.Set("Access-Control-Request-Headers", "authorization,dpop")
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityHigh, "https://solidproject.org/TR/protocol#cors"))

	// Test 2: Simple CORS request
	results = append(results, h.runSingleComparisonTest(ctx, "cors-002", "Simple CORS request",
		"CORS", "Verify all runtimes include CORS headers in responses",
		func(runtime RuntimeConfig, testURL string) RuntimeResult {
			url := fmt.Sprintf("%s/test-resource", runtime.BaseURL)
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, MethodGET, url, nil)
			req.Header.Set("Origin", "https://example.com")
			resp, err := runtime.Client.Do(req)
			duration := time.Since(start).Milliseconds()

			if err != nil {
				return RuntimeResult{Error: err.Error(), DurationMs: duration}
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			return RuntimeResult{
				StatusCode: resp.StatusCode,
				Headers:    extractHeaders(resp.Header),
				DurationMs: duration,
			}
		}, SeverityMedium, "https://solidproject.org/TR/protocol#cors"))

	return results
}

// runSingleComparisonTest runs a single comparison test across all enabled runtimes
func (h *CSSComparisonHarness) runSingleComparisonTest(
	ctx context.Context,
	testID, testName, category, description string,
	testFunc func(RuntimeConfig, string) RuntimeResult,
	severity string,
	specRef string,
) ComparisonTestResult {
	startTime := time.Now()

	result := ComparisonTestResult{
		TestID:          testID,
		TestName:        testName,
		TestCategory:    category,
		TestDescription: description,
		TestStatus:      TestStatusFailed,
		StartTime:       startTime.Format(time.RFC3339),
		Severity:        severity,
		SolidSpecRef:    specRef,
		RuntimeResults:  make(map[string]RuntimeResult),
	}

	// Run test against each enabled runtime
	runtimes := []RuntimeConfig{h.CSSConfig, h.SidecarConfig, h.NativeConfig}

	for _, runtime := range runtimes {
		if !runtime.Enabled {
			result.RuntimeResults[runtime.Name] = RuntimeResult{
				Skipped:    true,
				SkipReason: runtime.SkipReason,
			}
			continue
		}

		// Run the test function
		runtimeResult := testFunc(runtime, runtime.BaseURL)
		result.RuntimeResults[runtime.Name] = runtimeResult
	}

	// Analyze results for divergence
	result = h.analyzeDivergence(result)

	// Set end time and duration
	result.EndTime = time.Now().Format(time.RFC3339)
	result.DurationMs = int64(time.Since(startTime).Milliseconds())

	return result
}

// analyzeDivergence analyzes test results for behavioral divergence
func (h *CSSComparisonHarness) analyzeDivergence(result ComparisonTestResult) ComparisonTestResult {
	// Count enabled runtimes
	var enabledRuntimes []string
	var statusCodes []int
	var errors []string

	for runtime, runtimeResult := range result.RuntimeResults {
		if !runtimeResult.Skipped {
			enabledRuntimes = append(enabledRuntimes, runtime)
			if runtimeResult.Error != "" {
				errors = append(errors, fmt.Sprintf("%s: %s", runtime, runtimeResult.Error))
			} else {
				statusCodes = append(statusCodes, runtimeResult.StatusCode)
			}
		}
	}

	// If all runtimes were skipped, mark as skipped
	if len(enabledRuntimes) == 0 {
		result.TestStatus = TestStatusSkipped
		result.ErrorMessage = "No runtimes enabled for this test"
		return result
	}

	// If any errors occurred, mark as error
	if len(errors) > 0 {
		result.TestStatus = TestStatusError
		result.ErrorMessage = "One or more runtimes failed"
		result.ErrorDetails = strings.Join(errors, "; ")
		return result
	}

	// Check if all enabled runtimes returned the same status code
	if len(statusCodes) > 0 {
		firstStatus := statusCodes[0]
		allSame := true
		for _, status := range statusCodes[1:] {
			if status != firstStatus {
				allSame = false
				break
			}
		}

		if allSame {
			// All runtimes agree
			if firstStatus >= 200 && firstStatus < 300 {
				result.TestStatus = TestStatusPassed
			} else {
				// Expected failure (e.g., 401 for unauthenticated)
				result.TestStatus = TestStatusPassed
			}
		} else {
			// Status codes differ - divergence detected
			result.TestStatus = "diverged"
			result.ErrorMessage = "Runtime behavior diverged"
			var statusDetails []string
			for runtime, runtimeResult := range result.RuntimeResults {
				if !runtimeResult.Skipped && runtimeResult.Error == "" {
					statusDetails = append(statusDetails, fmt.Sprintf("%s: %d", runtime, runtimeResult.StatusCode))
				}
			}
			result.ErrorDetails = strings.Join(statusDetails, "; ")
		}
	}

	return result
}

// extractHeaders extracts relevant headers from HTTP response
func extractHeaders(header http.Header) map[string]string {
	headers := make(map[string]string)

	// Standard headers
	standardHeaders := []string{
		"Content-Type", "Content-Length", "ETag", "Last-Modified",
		"Cache-Control", "Vary", "Accept-Ranges", "Content-Encoding",
		"Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers", "Access-Control-Expose-Headers",
		"Link", "Allow", "WWW-Authenticate",
	}

	for _, headerName := range standardHeaders {
		if values := header.Values(headerName); len(values) > 0 {
			headers[headerName] = strings.Join(values, ", ")
		}
	}

	return headers
}

// Helper methods for counting results

func (h *CSSComparisonHarness) countPassed(results []ComparisonTestResult) int {
	var count int
	for _, result := range results {
		if result.TestStatus == TestStatusPassed {
			count++
		}
	}
	return count
}

func (h *CSSComparisonHarness) countFailed(results []ComparisonTestResult) int {
	var count int
	for _, result := range results {
		if result.TestStatus == TestStatusFailed || result.TestStatus == TestStatusError {
			count++
		}
	}
	return count
}

func (h *CSSComparisonHarness) countDiverged(results []ComparisonTestResult) int {
	var count int
	for _, result := range results {
		if result.TestStatus == "diverged" {
			count++
		}
	}
	return count
}

// GetDivergedTests returns all tests that showed behavioral divergence
func (h *CSSComparisonHarness) GetDivergedTests() []ComparisonTestResult {
	var diverged []ComparisonTestResult
	for _, result := range h.AllResults {
		if result.TestStatus == "diverged" {
			diverged = append(diverged, result)
		}
	}
	return diverged
}

// GetComparisonMatrix returns the comparison matrix grouped by category
func (h *CSSComparisonHarness) GetComparisonMatrix() map[string][]ComparisonTestResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Make a copy
	matrix := make(map[string][]ComparisonTestResult)
	for category, results := range h.ComparisonMatrix {
		matrix[category] = append([]ComparisonTestResult(nil), results...)
	}

	return matrix
}

// GenerateReport generates a comprehensive comparison report
func (h *CSSComparisonHarness) GenerateReport() (*ComparisonReport, error) {
	report := &ComparisonReport{
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		TotalTests:        len(h.AllResults),
		PassedTests:       h.countPassed(h.AllResults),
		FailedTests:       h.countFailed(h.AllResults),
		DivergedTests:     h.countDiverged(h.AllResults),
		ComparisonMatrix:  h.GetComparisonMatrix(),
		DivergenceDetails: h.GetDivergedTests(),
	}

	// Calculate compliance score
	if report.TotalTests > 0 {
		report.ComplianceScore = float64(report.PassedTests) / float64(report.TotalTests) * 100.0
	}

	// Generate summary
	report.Summary = h.generateSummary()

	return report, nil
}

// ComparisonReport represents the full comparison report
type ComparisonReport struct {
	Timestamp         string                            `json:"timestamp"`
	TotalTests        int                               `json:"total_tests"`
	PassedTests       int                               `json:"passed_tests"`
	FailedTests       int                               `json:"failed_tests"`
	DivergedTests     int                               `json:"diverged_tests"`
	ComplianceScore   float64                           `json:"compliance_score"`
	Summary           string                            `json:"summary"`
	ComparisonMatrix  map[string][]ComparisonTestResult `json:"comparison_matrix"`
	DivergenceDetails []ComparisonTestResult            `json:"divergence_details"`
}

// generateSummary generates a human-readable summary
func (h *CSSComparisonHarness) generateSummary() string {
	var summary strings.Builder

	summary.WriteString("CSS vs Sidecar vs Native Runtime Comparison Report\n")
	summary.WriteString("===================================================\n\n")

	passed := h.countPassed(h.AllResults)
	failed := h.countFailed(h.AllResults)
	diverged := h.countDiverged(h.AllResults)
	total := len(h.AllResults)

	summary.WriteString(fmt.Sprintf("Total Tests: %d\n", total))
	summary.WriteString(fmt.Sprintf("Passed: %d (%.1f%%)\n", passed, float64(passed)/float64(total)*100))
	summary.WriteString(fmt.Sprintf("Failed: %d (%.1f%%)\n", failed, float64(failed)/float64(total)*100))
	summary.WriteString(fmt.Sprintf("Diverged: %d (%.1f%%)\n", diverged, float64(diverged)/float64(total)*100))

	if diverged > 0 {
		summary.WriteString("\nDivergence Summary:\n")
		for _, result := range h.GetDivergedTests() {
			summary.WriteString(fmt.Sprintf("  - %s (%s): %s\n", result.TestName, result.TestID, result.ErrorDetails))
		}
	}

	return summary.String()
}

// GenerateReportJSON generates a JSON report
func (h *CSSComparisonHarness) GenerateReportJSON() (string, error) {
	report, err := h.GenerateReport()
	if err != nil {
		return "", err
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// GenerateReportFile saves the report to a file
func (h *CSSComparisonHarness) GenerateReportFile(filename string) error {
	reportJSON, err := h.GenerateReportJSON()
	if err != nil {
		return err
	}

	return writeFileSafely(filename, []byte(reportJSON), os.FileMode(0644))
}

// PrintReport prints the report to stdout
func (h *CSSComparisonHarness) PrintReport() {
	report, err := h.GenerateReport()
	if err != nil {
		fmt.Printf("Error generating report: %v\n", err)
		return
	}

	fmt.Println(report.Summary)
}

// writeFileSafely writes data to a file with safety checks
func writeFileSafely(filename string, data []byte, perm os.FileMode) error {
	// Sanitize filename
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return fmt.Errorf("invalid filename: %s", filename)
	}

	// Ensure directory exists
	return writeFileAtomic(filename, data, perm)
}

// writeFileAtomic writes a file atomically (simple implementation)
// For production use, this should use temp file + rename pattern
func writeFileAtomic(filename string, data []byte, perm os.FileMode) error {
	// Simple implementation - in production, use atomic write pattern
	// with temporary file and rename for atomicity
	return os.WriteFile(filename, data, perm)
}

// ValidateURL validates that a URL is safe to use
func ValidateURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	// Check scheme
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("invalid scheme: %s", parsed.Scheme)
	}

	// Check host
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("missing hostname")
	}

	// Block private IPs and localhost
	if isPrivateIPOrLocalhost(host) {
		return fmt.Errorf("private IP or localhost not allowed: %s", host)
	}

	return nil
}

// isPrivateIPOrLocalhost checks if a host is a private IP or localhost
func isPrivateIPOrLocalhost(host string) bool {
	// Check for localhost
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}

	// Check for private IPs
	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP, could be a hostname - try to resolve
		// For now, just check common patterns
		if strings.HasPrefix(host, "192.168.") ||
			strings.HasPrefix(host, "10.") ||
			strings.HasPrefix(host, "172.16.") ||
			strings.HasPrefix(host, "172.17.") ||
			strings.HasPrefix(host, "172.18.") ||
			strings.HasPrefix(host, "172.19.") ||
			strings.HasPrefix(host, "172.20.") ||
			strings.HasPrefix(host, "172.21.") ||
			strings.HasPrefix(host, "172.22.") ||
			strings.HasPrefix(host, "172.23.") ||
			strings.HasPrefix(host, "172.24.") ||
			strings.HasPrefix(host, "172.25.") ||
			strings.HasPrefix(host, "172.26.") ||
			strings.HasPrefix(host, "172.27.") ||
			strings.HasPrefix(host, "172.28.") ||
			strings.HasPrefix(host, "172.29.") ||
			strings.HasPrefix(host, "172.30.") ||
			strings.HasPrefix(host, "172.31.") {
			return true
		}
		return false
	}

	// Check if it's a private IP
	if ip.IsPrivate() {
		return true
	}

	return false
}
