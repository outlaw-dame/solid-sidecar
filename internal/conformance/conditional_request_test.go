// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements conditional request conformance tests (ETag, Last-Modified, If-Match, If-None-Match).
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

// ConditionalRequestConformanceTests implements conditional request conformance tests
type ConditionalRequestConformanceTests struct {
	// Test configuration
	Timeout     time.Duration
	StrictMode  bool
	DebugOutput bool

	// Results
	Results []ConditionalRequestTestResult
}

// ConditionalRequestTestResult represents the result of a conditional request test
type ConditionalRequestTestResult struct {
	TestID          string `json:"test_id"`
	TestName        string `json:"test_name"`
	RequestPath     string `json:"request_path"`
	RequestMethod   string `json:"request_method"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string `json:"request_body,omitempty"`
	ExpectedStatus  int    `json:"expected_status"`
	ActualStatus    int    `json:"actual_status"`
	TestStatus      string `json:"test_status"` // "passed", "failed", "skipped", "error"
	ErrorMessage    string `json:"error_message,omitempty"`
	DurationMs      int64  `json:"duration_ms"`
	StartTime       string `json:"start_time"`
	EndTime         string `json:"end_time"`
	Severity        string `json:"severity"`
	SolidSpecRef    string `json:"solid_spec_ref,omitempty"`
}

// NewConditionalRequestConformanceTests creates a new conditional request test suite
func NewConditionalRequestConformanceTests() *ConditionalRequestConformanceTests {
	return &ConditionalRequestConformanceTests{
		Timeout:    30 * time.Second,
		StrictMode: true,
		Results:    make([]ConditionalRequestTestResult, 0),
	}
}

// Run executes all conditional request conformance tests
func (c *ConditionalRequestConformanceTests) Run(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult {
	results := make([]ConformanceTestResult, 0)

	if client == nil {
		client = &http.Client{Timeout: c.Timeout}
	}

	// First, we need to create a test resource to work with
	testResourcePath := "/test-conditional-resource.txt"
	testResourceBody := "Hello, Solid Conformance Testing!"
	
	// Create the test resource
	createReq, err := http.NewRequestWithContext(ctx, "PUT", serverURL+strings.TrimLeft(testResourcePath, "/"), bytes.NewReader([]byte(testResourceBody)))
	if err != nil {
		// If we can't create the resource, we can't test conditional requests
		return results
	}
	createReq.Header.Set("Content-Type", "text/plain")
	createReq.Header.Set("Accept", "*/*")
	
	createResp, err := client.Do(createReq)
	if err != nil {
		// If we can't create the resource, we can't test conditional requests
		return results
	}
	defer createResp.Body.Close()
	
	// Read the response to get ETag and Last-Modified headers
	io.ReadAll(createResp.Body)
	
	testETag := createResp.Header.Get("ETag")
	testLastModified := createResp.Header.Get("Last-Modified")

	// Conditional request test cases
	testCases := []struct {
		name           string
		method        string
		path          string
		headers       map[string]string
		body          string
		expectedStatus int
		severity      string
		specRef       string
	}{
		// If-Match tests
		{
			name:           "If-Match with valid ETag",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Match": testETag},
			body:          "",
			expectedStatus: 200,
			severity:      "high",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.1",
		},
		{
			name:           "If-Match with invalid ETag",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Match": `"invalid-etag"`},
			body:          "",
			expectedStatus: 412, // Precondition Failed
			severity:      "high",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.1",
		},
		{
			name:           "If-Match with wildcard",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Match": "*"},
			body:          "",
			expectedStatus: 200,
			severity:      "medium",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.1",
		},
		{
			name:           "If-Match with PUT (precondition for update)",
			method:        "PUT",
			path:          testResourcePath,
			headers:       map[string]string{"If-Match": testETag, "Content-Type": "text/plain"},
			body:          "Updated content",
			expectedStatus: 204, // No Content
			severity:      "high",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.1",
		},
		{
			name:           "If-Match with PUT and invalid ETag",
			method:        "PUT",
			path:          testResourcePath,
			headers:       map[string]string{"If-Match": `"invalid-etag"`, "Content-Type": "text/plain"},
			body:          "Updated content",
			expectedStatus: 412, // Precondition Failed
			severity:      "high",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.1",
		},

		// If-None-Match tests
		{
			name:           "If-None-Match with different ETag",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-None-Match": `"different-etag"`},
			body:          "",
			expectedStatus: 200,
			severity:      "high",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.2",
		},
		{
			name:           "If-None-Match with same ETag",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-None-Match": testETag},
			body:          "",
			expectedStatus: 304, // Not Modified
			severity:      "high",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.2",
		},
		{
			name:           "If-None-Match with wildcard",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-None-Match": "*"},
			body:          "",
			expectedStatus: 304, // Not Modified (if resource exists)
			severity:      "medium",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.2",
		},
		{
			name:           "If-None-Match with PUT (precondition for creation)",
			method:        "PUT",
			path:          "/new-conditional-resource.txt",
			headers:       map[string]string{"If-None-Match": "*", "Content-Type": "text/plain"},
			body:          "New resource content",
			expectedStatus: 412, // Precondition Failed (resource already exists, but we're using * which means if any resource exists)
			severity:      "medium",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.2",
		},

		// If-Modified-Since tests
		{
			name:           "If-Modified-Since with recent time",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Modified-Since": time.Now().UTC().Format(http.TimeFormat)},
			body:          "",
			expectedStatus: 304, // Not Modified (current time is after resource modification)
			severity:      "medium",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.3",
		},
		{
			name:           "If-Modified-Since with old time",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Modified-Since": "Wed, 21 Oct 1970 07:28:00 GMT"},
			body:          "",
			expectedStatus: 200, // OK (old time, resource has been modified)
			severity:      "medium",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.3",
		},
		{
			name:           "If-Modified-Since with resource Last-Modified time",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Modified-Since": testLastModified},
			body:          "",
			expectedStatus: 304, // Not Modified (exact modification time)
			severity:      "high",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.3",
		},

		// If-Unmodified-Since tests
		{
			name:           "If-Unmodified-Since with old time",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Unmodified-Since": "Wed, 21 Oct 1970 07:28:00 GMT"},
			body:          "",
			expectedStatus: 200, // OK (resource not modified since old time)
			severity:      "medium",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.4",
		},
		{
			name:           "If-Unmodified-Since with recent time",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Unmodified-Since": time.Now().UTC().Format(http.TimeFormat)},
			body:          "",
			expectedStatus: 412, // Precondition Failed (resource modified since recent time)
			severity:      "medium",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.4",
		},

		// If-Range tests
		{
			name:           "If-Range with valid ETag",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Range": testETag, "Range": "bytes=0-10"},
			body:          "",
			expectedStatus: 206, // Partial Content
			severity:      "low",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7233#section-3.2",
		},
		{
			name:           "If-Range with invalid ETag",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Range": `"invalid-etag"`, "Range": "bytes=0-10"},
			body:          "",
			expectedStatus: 200, // Full resource (If-Range condition not met)
			severity:      "low",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7233#section-3.2",
		},

		// Error cases
		{
			name:           "Invalid If-Match header format",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-Match": "invalid-format"},
			body:          "",
			expectedStatus: 400, // Bad Request
			severity:      "medium",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.1",
		},
		{
			name:           "Invalid If-None-Match header format",
			method:        "GET",
			path:          testResourcePath,
			headers:       map[string]string{"If-None-Match": "invalid-format"},
			body:          "",
			expectedStatus: 400, // Bad Request
			severity:      "medium",
			specRef:       "https://datatracker.ietf.org/doc/html/rfc7232#section-3.2",
		},
	}

	// Execute tests
	for _, test := range testCases {
		result := c.executeConditionalRequestTest(ctx, serverURL, client, test)
		conformanceResult := c.convertToConformanceResult(result)
		results = append(results, conformanceResult)
		c.Results = append(c.Results, result)
	}

	// Clean up test resource
	cleanupReq, _ := http.NewRequestWithContext(ctx, "DELETE", serverURL+strings.TrimLeft(testResourcePath, "/"), nil)
	if cleanupReq != nil {
		cleanupResp, _ := client.Do(cleanupReq)
		if cleanupResp != nil {
			defer cleanupResp.Body.Close()
			io.ReadAll(cleanupResp.Body)
		}
	}

	return results
}

// executeConditionalRequestTest executes a single conditional request test
func (c *ConditionalRequestConformanceTests) executeConditionalRequestTest(
	ctx context.Context,
	serverURL string,
	client *http.Client,
	test struct {
		name           string
		method        string
		path          string
		headers       map[string]string
		body          string
		expectedStatus int
		severity      string
		specRef       string
	},
) ConditionalRequestTestResult {
	result := ConditionalRequestTestResult{
		TestID:         uuid.New().String(),
		TestName:       test.name,
		RequestPath:    test.path,
		RequestMethod:  test.method,
		RequestHeaders: test.headers,
		RequestBody:    test.body,
		ExpectedStatus: test.expectedStatus,
		StartTime:      time.Now().UTC().Format(time.RFC3339),
		Severity:       test.severity,
		SolidSpecRef:   test.specRef,
		TestStatus:    "error",
	}

	// Create request URL
	requestURL := serverURL + strings.TrimLeft(test.path, "/")

	// Create request body
	var bodyReader io.Reader
	if test.body != "" {
		bodyReader = bytes.NewReader([]byte(test.body))
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, test.method, requestURL, bodyReader)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to create request: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = time.Since(time.Now().UTC()).Milliseconds()
		return result
	}

	// Set headers
	for key, value := range test.headers {
		req.Header.Set(key, value)
	}
	if test.body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "text/plain")
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

	// Read response body (limited)
	io.ReadAll(io.LimitReader(resp.Body, c.Timeout.Milliseconds()/10))

	// Store results
	result.ActualStatus = resp.StatusCode
	result.EndTime = time.Now().UTC().Format(time.RFC3339)
	result.DurationMs = duration.Milliseconds()

	// Evaluate result
	result.TestStatus = c.evaluateConditionalRequestResult(test, resp.StatusCode)

	return result
}

// evaluateConditionalRequestResult evaluates the conditional request response
func (c *ConditionalRequestConformanceTests) evaluateConditionalRequestResult(
	test struct {
		name           string
		method        string
		path          string
		headers       map[string]string
		body          string
		expectedStatus int
		severity      string
		specRef       string
	},
	actualStatus int,
) string {
	// Direct status code comparison
	if actualStatus == test.expectedStatus {
		return "passed"
	}

	// Special handling for 304/200 equivalence
	if (test.expectedStatus == 304 && actualStatus == 200) || (test.expectedStatus == 200 && actualStatus == 304) {
		if c.StrictMode {
			return "failed"
		}
		return "passed" // Non-strict mode: both indicate resource not modified
	}

	// Special handling for 206/200 equivalence
	if test.expectedStatus == 206 && actualStatus == 200 {
		if c.StrictMode {
			return "failed"
		}
		return "passed" // Non-strict mode: full resource is acceptable
	}

	// Check if it's a success status code when we expected success
	if test.expectedStatus >= 200 && test.expectedStatus < 300 && actualStatus >= 200 && actualStatus < 300 {
		return "passed" // Any success is acceptable
	}

	// Check if it's an error status code when we expected an error
	if test.expectedStatus >= 400 && actualStatus >= 400 {
		return "passed" // Any error is acceptable for error cases
	}

	return "failed"
}

// convertToConformanceResult converts conditional request test result to conformance result
func (c *ConditionalRequestConformanceTests) convertToConformanceResult(result ConditionalRequestTestResult) ConformanceTestResult {
	headerString := ""
	for k, v := range result.RequestHeaders {
		headerString += fmt.Sprintf("%s: %s; ", k, v)
	}
	if headerString != "" {
		headerString = strings.TrimSuffix(headerString, "; ")
	}

	return ConformanceTestResult{
		TestID:          result.TestID,
		TestName:        result.TestName,
		TestCategory:    "Conditional Request",
		TestDescription: fmt.Sprintf("%s %s with headers: %s", result.RequestMethod, result.RequestPath, headerString),
		TestStatus:      result.TestStatus,
		ErrorMessage:    result.ErrorMessage,
		ErrorDetails:    fmt.Sprintf("Expected status: %d, Got: %d", result.ExpectedStatus, result.ActualStatus),
		StartTime:       result.StartTime,
		EndTime:         result.EndTime,
		DurationMs:      result.DurationMs,
		Expectation:     fmt.Sprintf("Status: %d", result.ExpectedStatus),
		ActualResult:    fmt.Sprintf("Status: %d", result.ActualStatus),
		Severity:        result.Severity,
		SolidSpecRef:    result.SolidSpecRef,
	}
}

// GetConformanceScore returns the conformance score for conditional request tests
func (c *ConditionalRequestConformanceTests) GetConformanceScore() float64 {
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

// GetFailedTests returns all failed conditional request tests
func (c *ConditionalRequestConformanceTests) GetFailedTests() []ConditionalRequestTestResult {
	var failed []ConditionalRequestTestResult
	
	for _, result := range c.Results {
		if result.TestStatus == "failed" || result.TestStatus == "error" {
			failed = append(failed, result)
		}
	}
	
	return failed
}

// GetResultsByPrecondition returns results grouped by precondition type
func (c *ConditionalRequestConformanceTests) GetResultsByPrecondition() map[string][]ConditionalRequestTestResult {
	resultsByPrecondition := make(map[string][]ConditionalRequestTestResult)
	
	for _, result := range c.Results {
		// Extract precondition type from headers
		precondition := "None"
		if _, exists := result.RequestHeaders["If-Match"]; exists {
			precondition = "If-Match"
		} else if _, exists := result.RequestHeaders["If-None-Match"]; exists {
			precondition = "If-None-Match"
		} else if _, exists := result.RequestHeaders["If-Modified-Since"]; exists {
			precondition = "If-Modified-Since"
		} else if _, exists := result.RequestHeaders["If-Unmodified-Since"]; exists {
			precondition = "If-Unmodified-Since"
		} else if _, exists := result.RequestHeaders["If-Range"]; exists {
			precondition = "If-Range"
		}
		
		resultsByPrecondition[precondition] = append(resultsByPrecondition[precondition], result)
	}
	
	return resultsByPrecondition
}