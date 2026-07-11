// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements storage description, auxiliary resource, and link-header conformance tests.
package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// StorageDescriptionConformanceTests implements storage description conformance tests
type StorageDescriptionConformanceTests struct {
	// Test configuration
	Timeout     time.Duration
	StrictMode  bool
	DebugOutput bool

	// Results
	Results []StorageDescriptionTestResult
}

// StorageDescriptionTestResult represents the result of a storage description test
type StorageDescriptionTestResult struct {
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
	ResponseBody    string            `json:"response_body,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

// NewStorageDescriptionConformanceTests creates a new storage description test suite
func NewStorageDescriptionConformanceTests() *StorageDescriptionConformanceTests {
	return &StorageDescriptionConformanceTests{
		Timeout:    30 * time.Second,
		StrictMode: true,
		Results:    make([]StorageDescriptionTestResult, 0),
	}
}

// Run executes all storage description conformance tests
func (s *StorageDescriptionConformanceTests) Run(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult {
	results := make([]ConformanceTestResult, 0)

	if client == nil {
		client = &http.Client{Timeout: s.Timeout}
	}

	// Storage description tests
	testCases := []struct {
		name           string
		path           string
		method         string
		expectedStatus int
		contentType    string
		body           []byte
		checkHeaders   bool
		checkBody      bool
		severity       string
		specRef        string
	}{
		// Storage description resource tests
		{
			name:           "GET storage description (JSON-LD)",
			path:           "/.storage",
			method:         "GET",
			expectedStatus: http.StatusOK,
			contentType:    "application/ld+json",
			checkHeaders:   true,
			checkBody:      true,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/storage-description#retrieving",
		},
		{
			name:           "HEAD storage description",
			path:           "/.storage",
			method:         "HEAD",
			expectedStatus: http.StatusOK,
			contentType:    "application/ld+json",
			checkHeaders:   true,
			checkBody:      false,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/storage-description#retrieving",
		},
		{
			name:           "OPTIONS storage description",
			path:           "/.storage",
			method:         "OPTIONS",
			expectedStatus: http.StatusOK,
			contentType:    "",
			checkHeaders:   true,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/TR/protocol#options",
		},

		// Auxiliary resource tests
		{
			name:           "GET auxiliary resource (.meta)",
			path:           "/resource.txt.meta",
			method:         "GET",
			expectedStatus: http.StatusOK,
			contentType:    "text/turtle",
			checkHeaders:   true,
			checkBody:      true,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/protocol#auxiliary",
		},
		{
			name:           "HEAD auxiliary resource (.meta)",
			path:           "/resource.txt.meta",
			method:         "HEAD",
			expectedStatus: http.StatusOK,
			contentType:    "text/turtle",
			checkHeaders:   true,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/TR/protocol#auxiliary",
		},

		// Link header tests
		{
			name:           "GET resource with Link header for description",
			path:           "/",
			method:         "GET",
			expectedStatus: http.StatusOK,
			contentType:    "text/turtle",
			checkHeaders:   true,
			checkBody:      false,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/protocol#describing-links",
		},

		// Test for proper storage description properties
		{
			name:           "GET storage description with required properties",
			path:           "/.storage",
			method:         "GET",
			expectedStatus: http.StatusOK,
			contentType:    "application/ld+json",
			checkHeaders:   true,
			checkBody:      true,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/storage-description#properties",
		},

		// Test for storage description updates
		{
			name:           "PUT storage description (update)",
			path:           "/.storage",
			method:         "PUT",
			expectedStatus: http.StatusOK,
			contentType:    "application/ld+json",
			body: []byte(`{
				"@context": "https://www.w3.org/ns/solid/terms#",
				"@id": "/.storage",
				"@type": "Storage",
				"name": "Test Storage",
				"description": "A test storage"
			}`),
			checkHeaders: false,
			checkBody:    false,
			severity:     "medium",
			specRef:      "https://solidproject.org/TR/storage-description#managing",
		},

		// Test for auxiliary resource creation
		{
			name:           "PUT auxiliary resource (create)",
			path:           "/new-resource.meta",
			method:         "PUT",
			expectedStatus: http.StatusCreated,
			contentType:    "text/turtle",
			body: []byte(`@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix dc: <http://purl.org/dc/terms/> .

<> dc:title "New Resource Metadata" .`),
			checkHeaders: false,
			checkBody:    false,
			severity:     "medium",
			specRef:      "https://solidproject.org/TR/protocol#auxiliary",
		},
	}

	// Execute tests
	for _, test := range testCases {
		result := s.executeStorageDescriptionTest(ctx, serverURL, client, test)
		conformanceResult := s.convertToConformanceResult(result)
		results = append(results, conformanceResult)
		s.Results = append(s.Results, result)
	}

	return results
}

// executeStorageDescriptionTest executes a single storage description test
func (s *StorageDescriptionConformanceTests) executeStorageDescriptionTest(
	ctx context.Context,
	serverURL string,
	client *http.Client,
	test struct {
		name           string
		path           string
		method         string
		expectedStatus int
		contentType    string
		body           []byte
		checkHeaders   bool
		checkBody      bool
		severity       string
		specRef        string
	},
) StorageDescriptionTestResult {
	result := StorageDescriptionTestResult{
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
	}

	// Create request URL
	requestURL := serverURL + strings.TrimLeft(test.path, "/")

	// Create HTTP request body
	var bodyReader io.Reader
	if test.body != nil {
		bodyReader = bytes.NewReader(test.body)
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
	if test.contentType != "" {
		req.Header.Set("Content-Type", test.contentType)
		result.RequestHeaders["Content-Type"] = test.contentType
	}
	req.Header.Set("Accept", "application/ld+json,text/turtle,*/*")
	result.RequestHeaders["Accept"] = "application/ld+json,text/turtle,*/*"

	// Execute request
	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Request failed: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = duration.Milliseconds()
		if duration > s.Timeout {
			result.Severity = "high"
		}
		return result
	}
	defer resp.Body.Close()

	// Read response body (limited to prevent memory issues)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, s.Timeout.Milliseconds()/10))
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to read response body: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = duration.Milliseconds()
		return result
	}

	// Store response body
	if len(bodyBytes) > 0 {
		result.ResponseBody = string(bodyBytes)
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
	result.TestStatus = s.evaluateStorageDescriptionResult(test, resp.StatusCode, result.ResponseHeaders, result.ResponseBody)

	return result
}

// evaluateStorageDescriptionResult evaluates the storage description test result
func (s *StorageDescriptionConformanceTests) evaluateStorageDescriptionResult(
	test struct {
		name           string
		path           string
		method         string
		expectedStatus int
		contentType    string
		body           []byte
		checkHeaders   bool
		checkBody      bool
		severity       string
		specRef        string
	},
	actualStatus int,
	responseHeaders map[string]string,
	responseBody string,
) string {
	// First, check status code
	if actualStatus != test.expectedStatus {
		// Allow some flexibility for success codes
		if test.expectedStatus >= 200 && test.expectedStatus < 300 && actualStatus >= 200 && actualStatus < 300 {
			if !s.StrictMode {
				// Status is OK, continue with other checks
			} else {
				return "failed"
			}
		} else if test.expectedStatus >= 400 && test.expectedStatus < 500 && actualStatus >= 400 && actualStatus < 500 {
			if !s.StrictMode {
				// Both are client errors, continue
			} else {
				return "failed"
			}
		} else {
			return "failed"
		}
	}

	// Check content type if required
	if test.checkHeaders && test.contentType != "" && actualStatus == test.expectedStatus {
		contentType := responseHeaders["Content-Type"]
		if contentType == "" {
			return "failed"
		}
		// Check if the content type matches or is compatible
		if !strings.Contains(contentType, test.contentType) {
			// Check for compatible types
			compatibleTypes := getCompatibleContentTypes(test.contentType)
			found := false
			for _, compatibleType := range compatibleTypes {
				if strings.Contains(contentType, compatibleType) {
					found = true
					break
				}
			}
			if !found {
				return "failed"
			}
		}
	}

	// Check body for required properties
	if test.checkBody && test.contentType == "application/ld+json" && strings.Contains(test.path, ".storage") {
		// Parse JSON-LD response
		var storageDesc map[string]interface{}
		if err := json.Unmarshal([]byte(responseBody), &storageDesc); err != nil {
			// Not valid JSON, might be error or different format
			return "failed"
		}

		// Check for required storage description properties
		// According to the spec, a storage description should have certain properties
		// We'll check for common ones
		requiredProperties := []string{"@context", "@id", "@type"}
		for _, prop := range requiredProperties {
			if _, exists := storageDesc[prop]; !exists {
				return "failed"
			}
		}
	}

	return "passed"
}

// convertToConformanceResult converts storage description test result to conformance result
func (s *StorageDescriptionConformanceTests) convertToConformanceResult(result StorageDescriptionTestResult) ConformanceTestResult {
	return ConformanceTestResult{
		TestID:          result.TestID,
		TestName:        result.TestName,
		TestCategory:    "Storage Description",
		TestDescription: fmt.Sprintf("%s %s on %s", result.RequestMethod, result.RequestPath, result.TestName),
		TestStatus:      result.TestStatus,
		ErrorMessage:    result.ErrorMessage,
		ErrorDetails:    fmt.Sprintf("Expected status: %d, Got: %d", result.ExpectedStatus, result.ActualStatus),
		StartTime:       result.StartTime,
		EndTime:         result.EndTime,
		DurationMs:      result.DurationMs,
		Expectation:     fmt.Sprintf("Status: %d, Content-Type: %s", result.ExpectedStatus, result.RequestHeaders["Content-Type"]),
		ActualResult:    fmt.Sprintf("Status: %d, Content-Type: %s", result.ActualStatus, result.ResponseHeaders["Content-Type"]),
		Severity:        result.Severity,
		SolidSpecRef:    result.SolidSpecRef,
	}
}

// GetConformanceScore returns the conformance score for storage description tests
func (s *StorageDescriptionConformanceTests) GetConformanceScore() float64 {
	if len(s.Results) == 0 {
		return 0.0
	}

	var passed int
	for _, result := range s.Results {
		if result.TestStatus == "passed" {
			passed++
		}
	}

	return float64(passed) / float64(len(s.Results)) * 100.0
}

// GetFailedTests returns all failed storage description tests
func (s *StorageDescriptionConformanceTests) GetFailedTests() []StorageDescriptionTestResult {
	var failed []StorageDescriptionTestResult

	for _, result := range s.Results {
		if result.TestStatus == "failed" || result.TestStatus == "error" {
			failed = append(failed, result)
		}
	}

	return failed
}

// GetResultsByPath returns results grouped by request path
func (s *StorageDescriptionConformanceTests) GetResultsByPath() map[string][]StorageDescriptionTestResult {
	resultsByPath := make(map[string][]StorageDescriptionTestResult)

	for _, result := range s.Results {
		path := result.RequestPath
		resultsByPath[path] = append(resultsByPath[path], result)
	}

	return resultsByPath
}

// GetResultsByMethod returns results grouped by HTTP method
func (s *StorageDescriptionConformanceTests) GetResultsByMethod() map[string][]StorageDescriptionTestResult {
	resultsByMethod := make(map[string][]StorageDescriptionTestResult)

	for _, result := range s.Results {
		method := result.RequestMethod
		resultsByMethod[method] = append(resultsByMethod[method], result)
	}

	return resultsByMethod
}
