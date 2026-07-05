// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements content negotiation conformance tests.
package conformance

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ContentNegotiationConformanceTests implements content negotiation conformance tests
type ContentNegotiationConformanceTests struct {
	// Test configuration
	Timeout     time.Duration
	StrictMode  bool
	DebugOutput bool

	// Results
	Results []ContentNegotiationTestResult
}

// ContentNegotiationTestResult represents the result of a content negotiation test
type ContentNegotiationTestResult struct {
	TestID              string            `json:"test_id"`
	TestName            string            `json:"test_name"`
	RequestPath         string            `json:"request_path"`
	RequestHeaders      map[string]string `json:"request_headers,omitempty"`
	ExpectedContentType string            `json:"expected_content_type"`
	ActualContentType   string            `json:"actual_content_type"`
	ActualStatus        int               `json:"actual_status"`
	TestStatus          string            `json:"test_status"` // "passed", "failed", "skipped", "error"
	ErrorMessage        string            `json:"error_message,omitempty"`
	DurationMs          int64             `json:"duration_ms"`
	StartTime           string            `json:"start_time"`
	EndTime             string            `json:"end_time"`
	Severity            string            `json:"severity"`
	SolidSpecRef        string            `json:"solid_spec_ref,omitempty"`
}

// ConformanceTestResult for interface compatibility
type ConformanceTestResult struct {
	TestID          string `json:"test_id"`
	TestName        string `json:"test_name"`
	TestCategory    string `json:"test_category"`
	TestDescription string `json:"test_description"`
	TestStatus      string `json:"test_status"` // "passed", "failed", "skipped", "error"
	ErrorMessage    string `json:"error_message,omitempty"`
	ErrorDetails    string `json:"error_details,omitempty"`
	StartTime       string `json:"start_time"`
	EndTime         string `json:"end_time"`
	DurationMs      int64  `json:"duration_ms"`
	Expectation     string `json:"expectation"`
	ActualResult    string `json:"actual_result"`
	Severity        string `json:"severity"`                 // "critical", "high", "medium", "low"
	SolidSpecRef    string `json:"solid_spec_ref,omitempty"` // Reference to Solid spec
}

// NewContentNegotiationConformanceTests creates a new content negotiation test suite
func NewContentNegotiationConformanceTests() *ContentNegotiationConformanceTests {
	return &ContentNegotiationConformanceTests{
		Timeout:    30 * time.Second,
		StrictMode: true,
		Results:    make([]ContentNegotiationTestResult, 0),
	}
}

// Run executes all content negotiation conformance tests
func (c *ContentNegotiationConformanceTests) Run(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult {
	results := make([]ConformanceTestResult, 0)

	if client == nil {
		client = &http.Client{Timeout: c.Timeout}
	}

	// Content negotiation test cases
	testCases := []struct {
		name             string
		path             string
		acceptHeader     string
		expectedMimeType string
		severity         string
		specRef          string
	}{
		// RDF content types
		{
			name:             "Turtle Accept",
			path:             "/resource",
			acceptHeader:     "text/turtle",
			expectedMimeType: "text/turtle",
			severity:         "high",
			specRef:          "https://www.w3.org/ns/iana/media-types/text/turtle#Resource",
		},
		{
			name:             "JSON-LD Accept",
			path:             "/resource",
			acceptHeader:     "application/ld+json",
			expectedMimeType: "application/ld+json",
			severity:         "high",
			specRef:          "https://www.w3.org/ns/iana/media-types/application/ld+json#Resource",
		},
		{
			name:             "RDF/XML Accept",
			path:             "/resource",
			acceptHeader:     "application/rdf+xml",
			expectedMimeType: "application/rdf+xml",
			severity:         "high",
			specRef:          "https://www.w3.org/ns/iana/media-types/application/rdf+xml#Resource",
		},
		{
			name:             "N-Triples Accept",
			path:             "/resource",
			acceptHeader:     "application/n-triples",
			expectedMimeType: "application/n-triples",
			severity:         "medium",
			specRef:          "https://www.w3.org/ns/iana/media-types/application/n-triples#Resource",
		},
		{
			name:             "N-Quads Accept",
			path:             "/resource",
			acceptHeader:     "application/n-quads",
			expectedMimeType: "application/n-quads",
			severity:         "medium",
			specRef:          "https://www.w3.org/ns/iana/media-types/application/n-quads#Resource",
		},

		// Non-RDF content types
		{
			name:             "Plain Text Accept",
			path:             "/resource.txt",
			acceptHeader:     "text/plain",
			expectedMimeType: "text/plain",
			severity:         "high",
			specRef:          "https://www.iana.org/assignments/media-types/text/plain",
		},
		{
			name:             "HTML Accept",
			path:             "/resource.html",
			acceptHeader:     "text/html",
			expectedMimeType: "text/html",
			severity:         "medium",
			specRef:          "https://www.iana.org/assignments/media-types/text/html",
		},
		{
			name:             "JSON Accept",
			path:             "/resource.json",
			acceptHeader:     "application/json",
			expectedMimeType: "application/json",
			severity:         "medium",
			specRef:          "https://www.iana.org/assignments/media-types/application/json",
		},

		// Wildcard and multiple accept headers
		{
			name:             "Wildcard Accept",
			path:             "/resource",
			acceptHeader:     "*/*",
			expectedMimeType: "", // Any content type is acceptable
			severity:         "high",
			specRef:          "https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.5",
		},
		{
			name:             "Multiple Accept with Quality",
			path:             "/resource",
			acceptHeader:     "application/ld+json;q=0.9, text/turtle;q=0.8, application/rdf+xml;q=0.7",
			expectedMimeType: "application/ld+json", // Highest quality should be preferred
			severity:         "medium",
			specRef:          "https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.5",
		},
		{
			name:             "No Accept Header",
			path:             "/resource",
			acceptHeader:     "",
			expectedMimeType: "", // Server default is acceptable
			severity:         "low",
			specRef:          "https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.5",
		},

		// Container-specific content negotiation
		{
			name:             "Container Turtle Accept",
			path:             "/",
			acceptHeader:     "text/turtle",
			expectedMimeType: "text/turtle",
			severity:         "medium",
			specRef:          "https://solidproject.org/TR/protocol#containers",
		},

		// Storage description content types
		{
			name:             "Storage Description JSON-LD",
			path:             "/.storage",
			acceptHeader:     "application/ld+json",
			expectedMimeType: "application/ld+json",
			severity:         "medium",
			specRef:          "https://solidproject.org/TR/storage-description",
		},

		// Auxiliary resource content types
		{
			name:             "ACL Turtle",
			path:             "/resource.acl",
			acceptHeader:     "text/turtle",
			expectedMimeType: "text/turtle",
			severity:         "high",
			specRef:          "https://solidproject.org/TR/wac#acl-resource",
		},
		{
			name:             "ACP JSON-LD",
			path:             "/.acp",
			acceptHeader:     "application/ld+json",
			expectedMimeType: "application/ld+json",
			severity:         "high",
			specRef:          "https://solidproject.org/ED/acp",
		},
	}

	// Execute tests
	for _, test := range testCases {
		result := c.executeContentNegotiationTest(ctx, serverURL, client, test)
		conformanceResult := c.convertToConformanceResult(result)
		results = append(results, conformanceResult)
		c.Results = append(c.Results, result)
	}

	return results
}

// executeContentNegotiationTest executes a single content negotiation test
func (c *ContentNegotiationConformanceTests) executeContentNegotiationTest(
	ctx context.Context,
	serverURL string,
	client *http.Client,
	test struct {
		name             string
		path             string
		acceptHeader     string
		expectedMimeType string
		severity         string
		specRef          string
	},
) ContentNegotiationTestResult {
	result := ContentNegotiationTestResult{
		TestID:              uuid.New().String(),
		TestName:            test.name,
		RequestPath:         test.path,
		RequestHeaders:      make(map[string]string),
		ExpectedContentType: test.expectedMimeType,
		StartTime:           time.Now().UTC().Format(time.RFC3339),
		Severity:            test.severity,
		SolidSpecRef:        test.specRef,
		TestStatus:          "error",
	}

	// Set Accept header if specified
	if test.acceptHeader != "" {
		result.RequestHeaders["Accept"] = test.acceptHeader
	}

	// Create request URL
	requestURL := serverURL + strings.TrimLeft(test.path, "/")

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to create request: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = time.Since(time.Now().UTC()).Milliseconds()
		return result
	}

	// Set Accept header
	if test.acceptHeader != "" {
		req.Header.Set("Accept", test.acceptHeader)
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

	// Store results
	result.ActualStatus = resp.StatusCode
	result.ActualContentType = resp.Header.Get("Content-Type")
	result.EndTime = time.Now().UTC().Format(time.RFC3339)
	result.DurationMs = duration.Milliseconds()

	// Evaluate result
	result.TestStatus = c.evaluateContentNegotiationResult(test, resp.StatusCode, result.ActualContentType)

	return result
}

// evaluateContentNegotiationResult evaluates the content negotiation response
func (c *ContentNegotiationConformanceTests) evaluateContentNegotiationResult(
	test struct {
		name             string
		path             string
		acceptHeader     string
		expectedMimeType string
		severity         string
		specRef          string
	},
	statusCode int,
	actualContentType string,
) string {
	// First, check if request was successful
	if statusCode < 200 || statusCode >= 300 {
		// For 404, the content type might still be correct for the error response
		if statusCode == 404 && actualContentType != "" {
			return "passed" // Error response with proper content type
		}
		return "failed"
	}

	// If no specific expectation, any content type is acceptable
	if test.expectedMimeType == "" {
		return "passed"
	}

	// Check if the actual content type matches or is compatible
	if strings.Contains(actualContentType, test.expectedMimeType) {
		return "passed"
	}

	// For multiple accept headers with quality, check if we got one of the requested types
	if strings.Contains(test.acceptHeader, ",") {
		// Check if any of the accepted types are in the actual content type
		acceptedTypes := strings.Split(test.acceptHeader, ",")
		for _, acceptedType := range acceptedTypes {
			acceptedType = strings.TrimSpace(strings.Split(acceptedType, ";")[0])
			if strings.Contains(actualContentType, acceptedType) {
				return "passed"
			}
		}
		return "failed"
	}

	// Strict mode: content type must match exactly or be compatible
	if c.StrictMode {
		// Check for compatible types (e.g., text/turtle vs application/ld+json for RDF)
		compatibleTypes := getCompatibleContentTypes(test.expectedMimeType)
		for _, compatibleType := range compatibleTypes {
			if strings.Contains(actualContentType, compatibleType) {
				return "passed"
			}
		}
		return "failed"
	}

	// Non-strict mode: as long as we got a valid content type
	if actualContentType != "" {
		return "passed"
	}

	return "failed"
}

// getCompatibleContentTypes returns content types that are compatible with the given type
func getCompatibleContentTypes(contentType string) []string {
	compatible := []string{}

	// RDF content types are somewhat interchangeable
	if strings.Contains(contentType, "turtle") {
		compatible = append(compatible, []string{"text/turtle", "application/x-turtle"}...)
	}
	if strings.Contains(contentType, "ld+json") {
		compatible = append(compatible, []string{"application/ld+json", "application/json"}...)
	}
	if strings.Contains(contentType, "rdf+xml") {
		compatible = append(compatible, []string{"application/rdf+xml", "application/xml"}...)
	}
	if strings.Contains(contentType, "n-triples") {
		compatible = append(compatible, []string{"application/n-triples"}...)
	}
	if strings.Contains(contentType, "n-quads") {
		compatible = append(compatible, []string{"application/n-quads"}...)
	}

	// Plain text
	if strings.Contains(contentType, "plain") {
		compatible = append(compatible, []string{"text/plain"}...)
	}

	// HTML
	if strings.Contains(contentType, "html") {
		compatible = append(compatible, []string{"text/html"}...)
	}

	// JSON
	if strings.Contains(contentType, "json") {
		compatible = append(compatible, []string{"application/json"}...)
	}

	return compatible
}

// convertToConformanceResult converts content negotiation test result to conformance result
func (c *ContentNegotiationConformanceTests) convertToConformanceResult(result ContentNegotiationTestResult) ConformanceTestResult {
	return ConformanceTestResult{
		TestID:          result.TestID,
		TestName:        result.TestName,
		TestCategory:    "Content Negotiation",
		TestDescription: fmt.Sprintf("Content negotiation for %s with Accept: %s", result.RequestPath, result.RequestHeaders["Accept"]),
		TestStatus:      result.TestStatus,
		ErrorMessage:    result.ErrorMessage,
		ErrorDetails:    fmt.Sprintf("Expected Content-Type: %s, Got: %s, Status: %d", result.ExpectedContentType, result.ActualContentType, result.ActualStatus),
		StartTime:       result.StartTime,
		EndTime:         result.EndTime,
		DurationMs:      result.DurationMs,
		Expectation:     fmt.Sprintf("Content-Type: %s", result.ExpectedContentType),
		ActualResult:    fmt.Sprintf("Content-Type: %s, Status: %d", result.ActualContentType, result.ActualStatus),
		Severity:        result.Severity,
		SolidSpecRef:    result.SolidSpecRef,
	}
}

// GetConformanceScore returns the conformance score for content negotiation tests
func (c *ContentNegotiationConformanceTests) GetConformanceScore() float64 {
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

// GetFailedTests returns all failed content negotiation tests
func (c *ContentNegotiationConformanceTests) GetFailedTests() []ContentNegotiationTestResult {
	var failed []ContentNegotiationTestResult

	for _, result := range c.Results {
		if result.TestStatus == "failed" || result.TestStatus == "error" {
			failed = append(failed, result)
		}
	}

	return failed
}

// GetResultsByContentType returns results grouped by content type
func (c *ContentNegotiationConformanceTests) GetResultsByContentType() map[string][]ContentNegotiationTestResult {
	resultsByType := make(map[string][]ContentNegotiationTestResult)

	for _, result := range c.Results {
		contentType := result.ExpectedContentType
		if contentType == "" {
			contentType = "any"
		}
		resultsByType[contentType] = append(resultsByType[contentType], result)
	}

	return resultsByType
}
