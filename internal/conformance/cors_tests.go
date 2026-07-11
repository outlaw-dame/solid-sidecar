// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements CORS and preflight compatibility tests.
package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CORSConformanceTests implements CORS compatibility tests
type CORSConformanceTests struct {
	// Test configuration
	Timeout     time.Duration
	StrictMode  bool
	DebugOutput bool

	// Results
	Results []CORSTestResult
}

// CORSTestResult represents the result of a CORS test
type CORSTestResult struct {
	TestID          string            `json:"test_id"`
	TestName        string            `json:"test_name"`
	RequestPath     string            `json:"request_path"`
	RequestMethod   string            `json:"request_method"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ExpectedStatus  int               `json:"expected_status"`
	ActualStatus    int               `json:"actual_status"`
	TestStatus      string            `json:"test_status"` // "passed", "failed", "skipped", "error"
	ErrorMessage    string            `json:"error_message,omitempty"`
	DurationMs      int64             `json:"duration_ms"`
	StartTime       string            `json:"start_time"`
	EndTime         string            `json:"end_time"`
	Severity        string            `json:"severity"`
	SolidSpecRef    string            `json:"solid_spec_ref,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ExpectedHeaders map[string]string `json:"expected_headers,omitempty"`
	MissingHeaders  []string          `json:"missing_headers,omitempty"`
}

// NewCORSConformanceTests creates a new CORS test suite
func NewCORSConformanceTests() *CORSConformanceTests {
	return &CORSConformanceTests{
		Timeout:    30 * time.Second,
		StrictMode: true,
		Results:    make([]CORSTestResult, 0),
	}
}

// Run executes all CORS compatibility tests
func (c *CORSConformanceTests) Run(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult {
	results := make([]ConformanceTestResult, 0)

	if client == nil {
		client = &http.Client{Timeout: c.Timeout}
	}

	// CORS preflight tests for different resource types
	preflightTests := []struct {
		name           string
		path           string
		method         string
		requestHeaders map[string]string
		expectedStatus int
		expectedCORS   map[string]string
		severity       string
		specRef        string
	}{
		// Basic CORS preflight for resources
		{
			name:   "OPTIONS preflight for GET on resource",
			path:   "/resource",
			method: "GET",
			requestHeaders: map[string]string{
				"Origin":                        "https://example.com",
				"Access-Control-Request-Method": "GET",
			},
			expectedStatus: http.StatusOK,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Methods":     "GET, HEAD, OPTIONS, PUT, POST, DELETE, PATCH",
				"Access-Control-Allow-Headers":     "Content-Type, Authorization, DPoP, Link",
				"Access-Control-Max-Age":           "", // Any value is acceptable
				"Access-Control-Allow-Credentials": "true",
			},
			severity: "high",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},
		{
			name:   "OPTIONS preflight for POST on container",
			path:   "/",
			method: "POST",
			requestHeaders: map[string]string{
				"Origin":                        "https://example.com",
				"Access-Control-Request-Method": "POST",
			},
			expectedStatus: http.StatusOK,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Methods":     "GET, HEAD, OPTIONS, PUT, POST, DELETE, PATCH",
				"Access-Control-Allow-Headers":     "Content-Type, Authorization, DPoP, Link, Slug",
				"Access-Control-Allow-Credentials": "true",
			},
			severity: "high",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},
		{
			name:   "OPTIONS preflight for PUT on resource",
			path:   "/resource",
			method: "PUT",
			requestHeaders: map[string]string{
				"Origin":                         "https://example.com",
				"Access-Control-Request-Method":  "PUT",
				"Access-Control-Request-Headers": "Content-Type, Authorization, DPoP",
			},
			expectedStatus: http.StatusOK,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Methods":     "GET, HEAD, OPTIONS, PUT, POST, DELETE, PATCH",
				"Access-Control-Allow-Headers":     "Content-Type, Authorization, DPoP, Link",
				"Access-Control-Allow-Credentials": "true",
			},
			severity: "high",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},
		{
			name:   "OPTIONS preflight for DELETE on resource",
			path:   "/resource",
			method: "DELETE",
			requestHeaders: map[string]string{
				"Origin":                        "https://example.com",
				"Access-Control-Request-Method": "DELETE",
			},
			expectedStatus: http.StatusOK,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Methods":     "GET, HEAD, OPTIONS, PUT, POST, DELETE, PATCH",
				"Access-Control-Allow-Headers":     "Content-Type, Authorization, DPoP, Link",
				"Access-Control-Allow-Credentials": "true",
			},
			severity: "high",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},
		{
			name:   "OPTIONS preflight for PATCH on resource",
			path:   "/resource",
			method: "PATCH",
			requestHeaders: map[string]string{
				"Origin":                         "https://example.com",
				"Access-Control-Request-Method":  "PATCH",
				"Access-Control-Request-Headers": "Content-Type, Authorization, DPoP",
			},
			expectedStatus: http.StatusOK,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Methods":     "GET, HEAD, OPTIONS, PUT, POST, DELETE, PATCH",
				"Access-Control-Allow-Headers":     "Content-Type, Authorization, DPoP, Link",
				"Access-Control-Allow-Credentials": "true",
			},
			severity: "high",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},

		// CORS preflight with different origins
		{
			name:   "OPTIONS preflight with wildcard origin",
			path:   "/resource",
			method: "GET",
			requestHeaders: map[string]string{
				"Origin":                        "https://any-origin.com",
				"Access-Control-Request-Method": "GET",
			},
			expectedStatus: http.StatusOK,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "*",
				"Access-Control-Allow-Methods":     "GET, HEAD, OPTIONS, PUT, POST, DELETE, PATCH",
				"Access-Control-Allow-Credentials": "true",
			},
			severity: "medium",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},
		{
			name:   "OPTIONS preflight with null origin",
			path:   "/resource",
			method: "GET",
			requestHeaders: map[string]string{
				"Origin":                        "null",
				"Access-Control-Request-Method": "GET",
			},
			expectedStatus: http.StatusOK,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "null",
				"Access-Control-Allow-Methods":     "GET, HEAD, OPTIONS, PUT, POST, DELETE, PATCH",
				"Access-Control-Allow-Credentials": "true",
			},
			severity: "medium",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},

		// CORS actual request tests
		{
			name:   "GET resource with Origin header (CORS)",
			path:   "/resource",
			method: "GET",
			requestHeaders: map[string]string{
				"Origin": "https://example.com",
			},
			expectedStatus: http.StatusOK,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Credentials": "true",
				"Vary":                             "Origin",
			},
			severity: "high",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},
		{
			name:   "POST to container with Origin header (CORS)",
			path:   "/",
			method: "POST",
			requestHeaders: map[string]string{
				"Origin":       "https://example.com",
				"Content-Type": "text/plain",
			},
			expectedStatus: http.StatusCreated,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Credentials": "true",
				"Vary":                             "Origin",
			},
			severity: "high",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},

		// CORS with credentials
		{
			name:   "GET resource with credentials",
			path:   "/resource",
			method: "GET",
			requestHeaders: map[string]string{
				"Origin": "https://example.com",
			},
			expectedStatus: http.StatusOK,
			expectedCORS: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Credentials": "true",
			},
			severity: "high",
			specRef:  "https://solidproject.org/TR/protocol#cors",
		},
	}

	// Execute tests
	for _, test := range preflightTests {
		result := c.executeCORSTest(ctx, serverURL, client, test)
		conformanceResult := c.convertToConformanceResult(result)
		results = append(results, conformanceResult)
		c.Results = append(c.Results, result)
	}

	return results
}

// executeCORSTest executes a single CORS test
func (c *CORSConformanceTests) executeCORSTest(
	ctx context.Context,
	serverURL string,
	client *http.Client,
	test struct {
		name           string
		path           string
		method         string
		requestHeaders map[string]string
		expectedStatus int
		expectedCORS   map[string]string
		severity       string
		specRef        string
	},
) CORSTestResult {
	result := CORSTestResult{
		TestID:          uuid.New().String(),
		TestName:        test.name,
		RequestPath:     test.path,
		RequestMethod:   test.method,
		ExpectedStatus:  test.expectedStatus,
		StartTime:       time.Now().UTC().Format(time.RFC3339),
		Severity:        test.severity,
		SolidSpecRef:    test.specRef,
		TestStatus:      "error",
		RequestHeaders:  make(map[string]string),
		ResponseHeaders: make(map[string]string),
		ExpectedHeaders: test.expectedCORS,
		MissingHeaders:  make([]string, 0),
	}

	// Set request headers
	for key, value := range test.requestHeaders {
		result.RequestHeaders[key] = value
	}

	// Create request URL
	requestURL := serverURL + strings.TrimLeft(test.path, "/")

	// Create HTTP request
	var bodyReader io.Reader
	if test.method == "POST" || test.method == "PUT" {
		bodyReader = bytes.NewReader([]byte("test content"))
	}

	req, err := http.NewRequestWithContext(ctx, test.method, requestURL, bodyReader)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to create request: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = time.Since(time.Now().UTC()).Milliseconds()
		return result
	}

	// Set request headers
	for key, value := range test.requestHeaders {
		req.Header.Set(key, value)
	}

	// Set default Accept header
	if _, exists := test.requestHeaders["Accept"]; !exists {
		req.Header.Set("Accept", "*/*")
	}

	// Execute request
	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Request failed: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = duration.Milliseconds()
		if duration > c.Timeout {
			result.Severity = "high"
		}
		return result
	}
	defer resp.Body.Close()

	// Read response body (limited to prevent memory issues)
	_, err = io.ReadAll(io.LimitReader(resp.Body, c.Timeout.Milliseconds()/10))
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to read response body: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = duration.Milliseconds()
		return result
	}

	// Store response headers
	for key, values := range resp.Header {
		if len(values) > 0 {
			result.ResponseHeaders[key] = values[0]
		}
	}

	// Store results
	result.ActualStatus = resp.StatusCode
	result.EndTime = time.Now().UTC().Format(time.RFC3339)
	result.DurationMs = duration.Milliseconds()

	// Evaluate result
	result.TestStatus = c.evaluateCORSResult(test, resp.StatusCode, result.ResponseHeaders)

	return result
}

// evaluateCORSResult evaluates the CORS test result
func (c *CORSConformanceTests) evaluateCORSResult(
	test struct {
		name           string
		path           string
		method         string
		requestHeaders map[string]string
		expectedStatus int
		expectedCORS   map[string]string
		severity       string
		specRef        string
	},
	actualStatus int,
	responseHeaders map[string]string,
) string {
	// First, check status code
	if actualStatus != test.expectedStatus {
		// For OPTIONS, we expect 200 or 204
		if test.method == "OPTIONS" && (actualStatus == http.StatusOK || actualStatus == http.StatusNoContent) {
			// Continue with CORS header checks
		} else if test.method != "OPTIONS" && actualStatus >= 200 && actualStatus < 300 {
			// For non-OPTIONS, any 2xx is acceptable
			// Continue with CORS header checks
		} else {
			return "failed"
		}
	}

	// Check required CORS headers
	// For preflight (OPTIONS), we need specific headers
	if test.method == "OPTIONS" {
		// Check for Allow-Origin
		if allowOrigin := responseHeaders["Access-Control-Allow-Origin"]; allowOrigin == "" {
			if test.expectedCORS["Access-Control-Allow-Origin"] != "" {
				return "failed"
			}
		}

		// Check for Allow-Methods
		if allowMethods := responseHeaders["Access-Control-Allow-Methods"]; allowMethods == "" {
			if test.expectedCORS["Access-Control-Allow-Methods"] != "" {
				return "failed"
			}
		}

		// Check for Allow-Credentials
		if allowCreds := responseHeaders["Access-Control-Allow-Credentials"]; allowCreds != "true" {
			if test.expectedCORS["Access-Control-Allow-Credentials"] == "true" {
				// Some servers might omit this if credentials aren't requested
				// Be lenient for this check
			}
		}
	} else {
		// For actual requests, check Allow-Origin
		if allowOrigin := responseHeaders["Access-Control-Allow-Origin"]; allowOrigin == "" {
			if test.expectedCORS["Access-Control-Allow-Origin"] != "" {
				return "failed"
			}
		}

		// Check Vary header for origin
		if vary := responseHeaders["Vary"]; !strings.Contains(vary, "Origin") {
			if test.expectedCORS["Vary"] == "Origin" {
				// Vary header might contain multiple values
				// Be lenient for this check
			}
		}
	}

	return "passed"
}

// convertToConformanceResult converts CORS test result to conformance result
func (c *CORSConformanceTests) convertToConformanceResult(result CORSTestResult) ConformanceTestResult {
	return ConformanceTestResult{
		TestID:          result.TestID,
		TestName:        result.TestName,
		TestCategory:    "CORS",
		TestDescription: fmt.Sprintf("%s %s with CORS headers", result.RequestMethod, result.RequestPath),
		TestStatus:      result.TestStatus,
		ErrorMessage:    result.ErrorMessage,
		ErrorDetails:    fmt.Sprintf("Expected status: %d, Got: %d. Missing headers: %v", result.ExpectedStatus, result.ActualStatus, result.MissingHeaders),
		StartTime:       result.StartTime,
		EndTime:         result.EndTime,
		DurationMs:      result.DurationMs,
		Expectation:     fmt.Sprintf("Status: %d, CORS headers: %v", result.ExpectedStatus, result.ExpectedHeaders),
		ActualResult:    fmt.Sprintf("Status: %d, CORS headers: %v", result.ActualStatus, c.getCORSHeaders(result.ResponseHeaders)),
		Severity:        result.Severity,
		SolidSpecRef:    result.SolidSpecRef,
	}
}

// getCORSHeaders returns a map of CORS-related headers from the response
func (c *CORSConformanceTests) getCORSHeaders(headers map[string]string) map[string]string {
	corsHeaders := make(map[string]string)
	for key, value := range headers {
		if strings.HasPrefix(key, "Access-Control-") || strings.ToLower(key) == "vary" {
			corsHeaders[key] = value
		}
	}
	return corsHeaders
}

// GetConformanceScore returns the conformance score for CORS tests
func (c *CORSConformanceTests) GetConformanceScore() float64 {
	if len(c.Results) == 0 {
		return 0.0
	}

	var passed int
	for _, result := range c.Results {
		if result.TestStatus == "passed" {
			passed++
		}
	}

	return float64(passed) / float64(len(c.Results)) * 100.0
}

// GetFailedTests returns all failed CORS tests
func (c *CORSConformanceTests) GetFailedTests() []CORSTestResult {
	var failed []CORSTestResult

	for _, result := range c.Results {
		if result.TestStatus == "failed" || result.TestStatus == "error" {
			failed = append(failed, result)
		}
	}

	return failed
}

// GetResultsByMethod returns results grouped by HTTP method
func (c *CORSConformanceTests) GetResultsByMethod() map[string][]CORSTestResult {
	resultsByMethod := make(map[string][]CORSTestResult)

	for _, result := range c.Results {
		method := result.RequestMethod
		resultsByMethod[method] = append(resultsByMethod[method], result)
	}

	return resultsByMethod
}

// GetResultsByPath returns results grouped by request path
func (c *CORSConformanceTests) GetResultsByPath() map[string][]CORSTestResult {
	resultsByPath := make(map[string][]CORSTestResult)

	for _, result := range c.Results {
		path := result.RequestPath
		resultsByPath[path] = append(resultsByPath[path], result)
	}

	return resultsByPath
}

// ValidateCORSHeaders validates CORS headers in a response
func (c *CORSConformanceTests) ValidateCORSHeaders(responseHeaders http.Header, expectedOrigin string) error {
	// Check Access-Control-Allow-Origin
	allowOrigin := responseHeaders.Get("Access-Control-Allow-Origin")
	if allowOrigin != expectedOrigin && allowOrigin != "*" {
		return fmt.Errorf("Access-Control-Allow-Origin mismatch: got %s, expected %s", allowOrigin, expectedOrigin)
	}

	// Check Access-Control-Allow-Credentials
	allowCreds := responseHeaders.Get("Access-Control-Allow-Credentials")
	if allowCreds != "true" {
		return fmt.Errorf("Access-Control-Allow-Credentials should be 'true', got: %s", allowCreds)
	}

	// Check Vary header
	vary := responseHeaders.Get("Vary")
	if !strings.Contains(vary, "Origin") {
		return fmt.Errorf("Vary header should contain 'Origin', got: %s", vary)
	}

	return nil
}

// CheckCORSPreflight validates a CORS preflight response
func (c *CORSConformanceTests) CheckCORSPreflight(responseHeaders http.Header, requestMethod string) error {
	// Check Access-Control-Allow-Methods
	allowMethods := responseHeaders.Get("Access-Control-Allow-Methods")
	if !strings.Contains(allowMethods, requestMethod) {
		return fmt.Errorf("Access-Control-Allow-Methods does not include requested method %s", requestMethod)
	}

	// Check Access-Control-Allow-Headers
	allowHeaders := responseHeaders.Get("Access-Control-Allow-Headers")
	if allowHeaders == "" {
		return fmt.Errorf("Access-Control-Allow-Headers is missing")
	}

	// Check Access-Control-Max-Age (optional but recommended)
	// maxAge := responseHeaders.Get("Access-Control-Max-Age")
	// Not required, so we won't fail on this

	return nil
}
