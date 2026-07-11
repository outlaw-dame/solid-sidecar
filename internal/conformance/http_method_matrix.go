// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements HTTP method matrix conformance tests.
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

// HTTPMethodMatrixConformanceTests implements HTTP method matrix conformance tests
type HTTPMethodMatrixConformanceTests struct {
	// Test configuration
	Timeout     time.Duration
	StrictMode  bool
	DebugOutput bool

	// Results
	Results []HTTPMethodMatrixTestResult
}

// HTTPMethodMatrixTestResult represents the result of an HTTP method matrix test
type HTTPMethodMatrixTestResult struct {
	TestID         string            `json:"test_id"`
	TestName       string            `json:"test_name"`
	Method         string            `json:"method"`
	TargetType     string            `json:"target_type"` // "resource", "container", "policy", "description"
	TargetURI      string            `json:"target_uri"`
	RequestBody    string            `json:"request_body,omitempty"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	ExpectedStatus int               `json:"expected_status"`
	ActualStatus   int               `json:"actual_status"`
	TestStatus     string            `json:"test_status"` // "passed", "failed", "skipped", "error"
	ErrorMessage   string            `json:"error_message,omitempty"`
	DurationMs     int64             `json:"duration_ms"`
	StartTime      string            `json:"start_time"`
	EndTime        string            `json:"end_time"`
	Severity       string            `json:"severity"`
	SolidSpecRef   string            `json:"solid_spec_ref,omitempty"`
}

// NewHTTPMethodMatrixConformanceTests creates a new HTTP method matrix test suite
func NewHTTPMethodMatrixConformanceTests() *HTTPMethodMatrixConformanceTests {
	return &HTTPMethodMatrixConformanceTests{
		Timeout:    30 * time.Second,
		StrictMode: true,
		Results:    make([]HTTPMethodMatrixTestResult, 0),
	}
}

// Run executes all HTTP method matrix conformance tests
func (h *HTTPMethodMatrixConformanceTests) Run(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult {
	results := make([]ConformanceTestResult, 0)

	if client == nil {
		client = &http.Client{Timeout: h.Timeout}
	}

	// Define test cases for each HTTP method and target type
	testCases := []struct {
		name           string
		method         string
		targetType     string
		targetPath     string
		requestBody    []byte
		contentType    string
		expectedStatus int
		severity       string
		specRef        string
	}{
		// Basic resource tests
		{
			name:           "GET on existing resource",
			method:         "GET",
			targetType:     "resource",
			targetPath:     "/test-resource.txt",
			expectedStatus: http.StatusOK,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/protocol#get",
		},
		{
			name:           "HEAD on existing resource",
			method:         "HEAD",
			targetType:     "resource",
			targetPath:     "/test-resource.txt",
			expectedStatus: http.StatusOK,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/protocol#head",
		},
		{
			name:           "PUT on new resource (create)",
			method:         "PUT",
			targetType:     "resource",
			targetPath:     "/new-resource.txt",
			requestBody:    []byte("New resource content"),
			contentType:    "text/plain",
			expectedStatus: http.StatusCreated,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/protocol#create-resource",
		},
		{
			name:           "DELETE on existing resource",
			method:         "DELETE",
			targetType:     "resource",
			targetPath:     "/test-resource.txt",
			expectedStatus: http.StatusNoContent,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/protocol#delete",
		},

		// Container tests
		{
			name:           "GET on container",
			method:         "GET",
			targetType:     "container",
			targetPath:     "/",
			expectedStatus: http.StatusOK,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/protocol#containers",
		},
		{
			name:           "POST to container (create with slug)",
			method:         "POST",
			targetType:     "container",
			targetPath:     "/",
			requestBody:    []byte("New resource content"),
			contentType:    "text/plain",
			expectedStatus: http.StatusCreated,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/protocol#create-resource",
		},

		// Non-existent resource tests
		{
			name:           "GET on non-existent resource",
			method:         "GET",
			targetType:     "resource",
			targetPath:     "/nonexistent-resource",
			expectedStatus: http.StatusNotFound,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/protocol#get",
		},
		{
			name:           "DELETE on non-existent resource",
			method:         "DELETE",
			targetType:     "resource",
			targetPath:     "/nonexistent-resource",
			expectedStatus: http.StatusNotFound,
			severity:       "medium",
			specRef:        "https://solidproject.org/TR/protocol#delete",
		},

		// Method not allowed tests
		{
			name:           "POST to resource (should fail)",
			method:         "POST",
			targetType:     "resource",
			targetPath:     "/test-resource.txt",
			expectedStatus: http.StatusMethodNotAllowed,
			severity:       "medium",
			specRef:        "https://solidproject.org/TR/protocol#post",
		},
	}

	// Execute tests
	for _, test := range testCases {
		result := h.executeHTTPMethodTest(ctx, serverURL, client, test)
		conformanceResult := h.convertToConformanceResult(result)
		results = append(results, conformanceResult)
		h.Results = append(h.Results, result)
	}

	return results
}

// executeHTTPMethodTest executes a single HTTP method test
func (h *HTTPMethodMatrixConformanceTests) executeHTTPMethodTest(
	ctx context.Context,
	serverURL string,
	client *http.Client,
	test struct {
		name           string
		method         string
		targetType     string
		targetPath     string
		requestBody    []byte
		contentType    string
		expectedStatus int
		severity       string
		specRef        string
	},
) HTTPMethodMatrixTestResult {
	result := HTTPMethodMatrixTestResult{
		TestID:         uuid.New().String(),
		TestName:       test.name,
		Method:         test.method,
		TargetType:     test.targetType,
		TargetURI:      test.targetPath,
		ExpectedStatus: test.expectedStatus,
		StartTime:      time.Now().UTC().Format(time.RFC3339),
		Severity:       test.severity,
		SolidSpecRef:   test.specRef,
		TestStatus:     "error",
		RequestHeaders: make(map[string]string),
	}

	// Set Content-Type header if we have a body
	if test.requestBody != nil && test.contentType != "" {
		result.RequestHeaders["Content-Type"] = test.contentType
	}

	// Store request body for result
	if test.requestBody != nil {
		result.RequestBody = string(test.requestBody)
	}

	// Create request URL
	requestURL := serverURL + strings.TrimLeft(test.targetPath, "/")

	// Create HTTP request body
	var bodyReader io.Reader
	if test.requestBody != nil {
		bodyReader = bytes.NewReader(test.requestBody)
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
	for key, value := range result.RequestHeaders {
		req.Header.Set(key, value)
	}

	// Set Accept header
	req.Header.Set("Accept", "*/*")

	// Execute request
	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Request failed: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = duration.Milliseconds()
		if duration > h.Timeout {
			result.Severity = "high"
		}
		return result
	}
	defer resp.Body.Close()

	// Read response body (limited to prevent memory issues)
	_, err = io.ReadAll(io.LimitReader(resp.Body, h.Timeout.Milliseconds()/10))
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to read response body: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = duration.Milliseconds()
		return result
	}

	// Store results
	result.ActualStatus = resp.StatusCode
	result.EndTime = time.Now().UTC().Format(time.RFC3339)
	result.DurationMs = duration.Milliseconds()

	// Evaluate result
	result.TestStatus = h.evaluateHTTPMethodResult(test.expectedStatus, result.ActualStatus)

	return result
}

// evaluateHTTPMethodResult evaluates the HTTP method test result
func (h *HTTPMethodMatrixConformanceTests) evaluateHTTPMethodResult(expectedStatus, actualStatus int) string {
	// Exact match
	if expectedStatus == actualStatus {
		return "passed"
	}

	// Special cases where multiple status codes are acceptable
	if expectedStatus == http.StatusOK && actualStatus == http.StatusNoContent {
		return "passed"
	}

	// PUT on new resource might return 201 or 200
	if expectedStatus == http.StatusCreated && actualStatus == http.StatusOK {
		return "passed"
	}

	// If we expected success (2xx) and got any 2xx, consider it passed for basic compatibility
	if expectedStatus >= 200 && expectedStatus < 300 && actualStatus >= 200 && actualStatus < 300 {
		if !h.StrictMode {
			return "passed"
		}
	}

	// If we expected client error (4xx) and got any 4xx
	if expectedStatus >= 400 && expectedStatus < 500 && actualStatus >= 400 && actualStatus < 500 {
		if !h.StrictMode {
			return "passed"
		}
	}

	return "failed"
}

// convertToConformanceResult converts HTTP method test result to conformance result
func (h *HTTPMethodMatrixConformanceTests) convertToConformanceResult(result HTTPMethodMatrixTestResult) ConformanceTestResult {
	return ConformanceTestResult{
		TestID:          result.TestID,
		TestName:        result.TestName,
		TestCategory:    "HTTP Method Matrix",
		TestDescription: fmt.Sprintf("%s %s on %s", result.Method, result.TargetURI, result.TargetType),
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

// GetConformanceScore returns the conformance score for HTTP method matrix tests
func (h *HTTPMethodMatrixConformanceTests) GetConformanceScore() float64 {
	if len(h.Results) == 0 {
		return 0.0
	}

	var passed int
	for _, result := range h.Results {
		if result.TestStatus == "passed" {
			passed++
		}
	}

	return float64(passed) / float64(len(h.Results)) * 100.0
}

// GetFailedTests returns all failed HTTP method matrix tests
func (h *HTTPMethodMatrixConformanceTests) GetFailedTests() []HTTPMethodMatrixTestResult {
	var failed []HTTPMethodMatrixTestResult

	for _, result := range h.Results {
		if result.TestStatus == "failed" || result.TestStatus == "error" {
			failed = append(failed, result)
		}
	}

	return failed
}

// GetResultsByMethod returns results grouped by HTTP method
func (h *HTTPMethodMatrixConformanceTests) GetResultsByMethod() map[string][]HTTPMethodMatrixTestResult {
	resultsByMethod := make(map[string][]HTTPMethodMatrixTestResult)

	for _, result := range h.Results {
		method := result.Method
		resultsByMethod[method] = append(resultsByMethod[method], result)
	}

	return resultsByMethod
}

// GetResultsByTargetType returns results grouped by target type
func (h *HTTPMethodMatrixConformanceTests) GetResultsByTargetType() map[string][]HTTPMethodMatrixTestResult {
	resultsByType := make(map[string][]HTTPMethodMatrixTestResult)

	for _, result := range h.Results {
		targetType := result.TargetType
		resultsByType[targetType] = append(resultsByType[targetType], result)
	}

	return resultsByType
}
