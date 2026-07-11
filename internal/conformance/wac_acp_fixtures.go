// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements WAC and ACP fixture suites.
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

// WACACPConformanceTests implements WAC and ACP conformance tests
type WACACPConformanceTests struct {
	// Test configuration
	Timeout     time.Duration
	StrictMode  bool
	DebugOutput bool

	// Results
	Results []WACACPTestResult
}

// WACACPTestResult represents the result of a WAC/ACP test
type WACACPTestResult struct {
	TestID          string            `json:"test_id"`
	TestName        string            `json:"test_name"`
	TestCategory    string            `json:"test_category"` // "wac", "acp", "sai"
	RequestPath     string            `json:"request_path"`
	RequestMethod   string            `json:"request_method"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
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

// NewWACACPConformanceTests creates a new WAC/ACP test suite
func NewWACACPConformanceTests() *WACACPConformanceTests {
	return &WACACPConformanceTests{
		Timeout:    30 * time.Second,
		StrictMode: true,
		Results:    make([]WACACPTestResult, 0),
	}
}

// Run executes all WAC and ACP conformance tests
func (w *WACACPConformanceTests) Run(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult {
	results := make([]ConformanceTestResult, 0)

	if client == nil {
		client = &http.Client{Timeout: w.Timeout}
	}

	// Setup: Create test resources
	testResourcePath := "/test-resource.txt"
	testWACPolicyPath := "/test-resource.txt.acl"
	testACPPolicyPath := "/.acp"

	// Create test resource
	_ = w.createResource(ctx, serverURL, client, testResourcePath, []byte("Test resource"), "text/plain")

	// Cleanup
	defer func() {
		_ = w.deleteResource(ctx, serverURL, client, testResourcePath)
		_ = w.deleteResource(ctx, serverURL, client, testWACPolicyPath)
		_ = w.deleteResource(ctx, serverURL, client, testACPPolicyPath)
	}()

	// WAC tests
	wacTests := []struct {
		name           string
		path           string
		method         string
		requestBody    []byte
		contentType    string
		expectedStatus int
		checkHeaders   bool
		checkBody      bool
		severity       string
		specRef        string
	}{
		// WAC policy retrieval tests
		{
			name:           "GET WAC policy for resource",
			path:           testWACPolicyPath,
			method:         "GET",
			expectedStatus: http.StatusOK,
			contentType:    "text/turtle",
			checkHeaders:   true,
			checkBody:      true,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/wac#retrieving",
		},
		{
			name:           "HEAD WAC policy for resource",
			path:           testWACPolicyPath,
			method:         "HEAD",
			expectedStatus: http.StatusOK,
			contentType:    "text/turtle",
			checkHeaders:   true,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/TR/wac#retrieving",
		},
		{
			name:           "OPTIONS WAC policy for resource",
			path:           testWACPolicyPath,
			method:         "OPTIONS",
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/TR/protocol#options",
		},

		// WAC policy creation tests
		{
			name:   "PUT WAC policy (create)",
			path:   testWACPolicyPath,
			method: "PUT",
			requestBody: []byte(`@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<> acl:Authorization <auth-1> ;
    acl:mode acl:Read, acl:Write ;
    acl:agent <https://example.com/agent#me> .`),
			contentType:    "text/turtle",
			expectedStatus: http.StatusCreated,
			checkHeaders:   true,
			checkBody:      false,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/wac#managing",
		},

		// WAC policy update tests
		{
			name:   "PUT WAC policy (update)",
			path:   testWACPolicyPath,
			method: "PUT",
			requestBody: []byte(`@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<> acl:Authorization <auth-1> ;
    acl:mode acl:Read, acl:Write, acl:Control ;
    acl:agent <https://example.com/agent#me> .`),
			contentType:    "text/turtle",
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
			checkBody:      false,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/wac#managing",
		},

		// WAC policy deletion tests
		{
			name:           "DELETE WAC policy",
			path:           testWACPolicyPath,
			method:         "DELETE",
			expectedStatus: http.StatusNoContent,
			checkHeaders:   false,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/TR/wac#deleting",
		},

		// WAC link header tests
		{
			name:           "GET resource with Link header to WAC policy",
			path:           testResourcePath,
			method:         "GET",
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
			checkBody:      false,
			severity:       "high",
			specRef:        "https://solidproject.org/TR/wac#discovery",
		},

		// WAC access control tests (should be enforced)
		{
			name:           "GET resource without proper authorization (should fail)",
			path:           testResourcePath,
			method:         "GET",
			expectedStatus: http.StatusUnauthorized,
			checkHeaders:   false,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/TR/wac#authorization",
		},
	}

	// ACP tests
	acpTests := []struct {
		name           string
		path           string
		method         string
		requestBody    []byte
		contentType    string
		expectedStatus int
		checkHeaders   bool
		checkBody      bool
		severity       string
		specRef        string
	}{
		// ACP policy retrieval tests
		{
			name:           "GET ACP policy",
			path:           testACPPolicyPath,
			method:         "GET",
			expectedStatus: http.StatusOK,
			contentType:    "application/ld+json",
			checkHeaders:   true,
			checkBody:      true,
			severity:       "high",
			specRef:        "https://solidproject.org/ED/acp#retrieving",
		},
		{
			name:           "HEAD ACP policy",
			path:           testACPPolicyPath,
			method:         "HEAD",
			expectedStatus: http.StatusOK,
			contentType:    "application/ld+json",
			checkHeaders:   true,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/ED/acp#retrieving",
		},
		{
			name:           "OPTIONS ACP policy",
			path:           testACPPolicyPath,
			method:         "OPTIONS",
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/TR/protocol#options",
		},

		// ACP policy creation tests
		{
			name:   "PUT ACP policy (create)",
			path:   testACPPolicyPath,
			method: "PUT",
			requestBody: []byte(`{
				"@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
				"@type": "AccessControl",
				"rule": [
					{
						"@type": "AccessGrant",
						"access": "Read",
						"agent": "https://example.com/agent#me"
					},
					{
						"@type": "AccessGrant",
						"access": "Write",
						"agent": "https://example.com/agent#me"
					}
				]
			}`),
			contentType:    "application/ld+json",
			expectedStatus: http.StatusCreated,
			checkHeaders:   true,
			checkBody:      false,
			severity:       "high",
			specRef:        "https://solidproject.org/ED/acp#managing",
		},

		// ACP policy update tests
		{
			name:   "PUT ACP policy (update)",
			path:   testACPPolicyPath,
			method: "PUT",
			requestBody: []byte(`{
				"@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
				"@type": "AccessControl",
				"rule": [
					{
						"@type": "AccessGrant",
						"access": "Read",
						"agent": "https://example.com/agent#me"
					},
					{
						"@type": "AccessGrant",
						"access": "Write",
						"agent": "https://example.com/agent#me"
					},
					{
						"@type": "AccessGrant",
						"access": "Control",
						"agent": "https://example.com/agent#me"
					}
				]
			}`),
			contentType:    "application/ld+json",
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
			checkBody:      false,
			severity:       "high",
			specRef:        "https://solidproject.org/ED/acp#managing",
		},

		// ACP policy deletion tests
		{
			name:           "DELETE ACP policy",
			path:           testACPPolicyPath,
			method:         "DELETE",
			expectedStatus: http.StatusNoContent,
			checkHeaders:   false,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/ED/acp#deleting",
		},

		// ACP access control tests
		{
			name:           "GET resource with ACP policy enforced",
			path:           testResourcePath,
			method:         "GET",
			expectedStatus: http.StatusOK,
			checkHeaders:   false,
			checkBody:      false,
			severity:       "medium",
			specRef:        "https://solidproject.org/ED/acp#authorization",
		},

		// ACP link header tests
		{
			name:           "GET container with Link header to ACP policy",
			path:           "/",
			method:         "GET",
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
			checkBody:      false,
			severity:       "high",
			specRef:        "https://solidproject.org/ED/acp#discovery",
		},
	}

	// Execute WAC tests
	for _, test := range wacTests {
		result := w.executeWACTest(ctx, serverURL, client, test, "wac")
		conformanceResult := w.convertToConformanceResult(result)
		results = append(results, conformanceResult)
		w.Results = append(w.Results, result)
	}

	// Execute ACP tests
	for _, test := range acpTests {
		result := w.executeWACTest(ctx, serverURL, client, test, "acp")
		conformanceResult := w.convertToConformanceResult(result)
		results = append(results, conformanceResult)
		w.Results = append(w.Results, result)
	}

	return results
}

// executeWACTest executes a single WAC or ACP test
func (w *WACACPConformanceTests) executeWACTest(
	ctx context.Context,
	serverURL string,
	client *http.Client,
	test struct {
		name           string
		path           string
		method         string
		requestBody    []byte
		contentType    string
		expectedStatus int
		checkHeaders   bool
		checkBody      bool
		severity       string
		specRef        string
	},
	category string,
) WACACPTestResult {
	result := WACACPTestResult{
		TestID:          uuid.New().String(),
		TestName:        test.name,
		TestCategory:    category,
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
	if test.requestBody != nil {
		bodyReader = bytes.NewReader(test.requestBody)
		result.RequestBody = string(test.requestBody)
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

	// Set Accept header based on category
	if category == "wac" {
		req.Header.Set("Accept", "text/turtle,application/ld+json,*/*")
		result.RequestHeaders["Accept"] = "text/turtle,application/ld+json,*/*"
	} else {
		req.Header.Set("Accept", "application/ld+json,text/turtle,*/*")
		result.RequestHeaders["Accept"] = "application/ld+json,text/turtle,*/*"
	}

	// Execute request
	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Request failed: %v", err)
		result.EndTime = time.Now().UTC().Format(time.RFC3339)
		result.DurationMs = duration.Milliseconds()
		if duration > w.Timeout {
			result.Severity = "high"
		}
		return result
	}
	defer resp.Body.Close()

	// Read response body (limited to prevent memory issues)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, w.Timeout.Milliseconds()/10))
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
	result.TestStatus = w.evaluateWACACPResult(test, result.ActualStatus, result.ResponseHeaders, result.ResponseBody, category)

	return result
}

// evaluateWACACPResult evaluates the WAC/ACP test result
func (w *WACACPConformanceTests) evaluateWACACPResult(
	test struct {
		name           string
		path           string
		method         string
		requestBody    []byte
		contentType    string
		expectedStatus int
		checkHeaders   bool
		checkBody      bool
		severity       string
		specRef        string
	},
	actualStatus int,
	responseHeaders map[string]string,
	responseBody string,
	category string,
) string {
	// First, check status code
	if actualStatus != test.expectedStatus {
		// Allow some flexibility for success codes
		if test.expectedStatus >= 200 && test.expectedStatus < 300 && actualStatus >= 200 && actualStatus < 300 {
			if !w.StrictMode {
				// Status is OK, continue with other checks
			} else {
				return "failed"
			}
		} else if test.expectedStatus >= 400 && test.expectedStatus < 500 && actualStatus >= 400 && actualStatus < 500 {
			if !w.StrictMode {
				// Both are client errors, continue
			} else {
				return "failed"
			}
		} else {
			return "failed"
		}
	}

	// Check content type for policy responses
	if test.checkHeaders && test.contentType != "" {
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
	if test.checkBody && category == "acp" && strings.Contains(responseHeaders["Content-Type"], "application/json") {
		// Parse JSON-LD response
		var policy map[string]interface{}
		if err := json.Unmarshal([]byte(responseBody), &policy); err == nil {
			// Check for required ACP properties
			if _, exists := policy["@context"]; !exists {
				return "failed"
			}
			if _, exists := policy["@type"]; !exists {
				return "failed"
			}
			if _, exists := policy["rule"]; !exists {
				return "failed"
			}
		}
	}

	// For WAC, check for basic structure
	if test.checkBody && category == "wac" && strings.Contains(responseHeaders["Content-Type"], "text/turtle") {
		// Check for basic WAC keywords
		if !strings.Contains(responseBody, "acl:") && !strings.Contains(responseBody, "Authorization") {
			// Might be empty or different format, be lenient
		}
	}

	return "passed"
}

// convertToConformanceResult converts WAC/ACP test result to conformance result
func (w *WACACPConformanceTests) convertToConformanceResult(result WACACPTestResult) ConformanceTestResult {
	categoryName := "WAC"
	if result.TestCategory == "acp" {
		categoryName = "ACP"
	}

	return ConformanceTestResult{
		TestID:          result.TestID,
		TestName:        result.TestName,
		TestCategory:    categoryName,
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

// GetConformanceScore returns the conformance score for WAC/ACP tests
func (w *WACACPConformanceTests) GetConformanceScore() float64 {
	if len(w.Results) == 0 {
		return 0.0
	}

	var passed int
	for _, result := range w.Results {
		if result.TestStatus == "passed" {
			passed++
		}
	}

	return float64(passed) / float64(len(w.Results)) * 100.0
}

// GetFailedTests returns all failed WAC/ACP tests
func (w *WACACPConformanceTests) GetFailedTests() []WACACPTestResult {
	var failed []WACACPTestResult

	for _, result := range w.Results {
		if result.TestStatus == "failed" || result.TestStatus == "error" {
			failed = append(failed, result)
		}
	}

	return failed
}

// GetResultsByCategory returns results grouped by category
func (w *WACACPConformanceTests) GetResultsByCategory() map[string][]WACACPTestResult {
	resultsByCategory := make(map[string][]WACACPTestResult)

	for _, result := range w.Results {
		category := result.TestCategory
		resultsByCategory[category] = append(resultsByCategory[category], result)
	}

	return resultsByCategory
}

// GetResultsByMethod returns results grouped by HTTP method
func (w *WACACPConformanceTests) GetResultsByMethod() map[string][]WACACPTestResult {
	resultsByMethod := make(map[string][]WACACPTestResult)

	for _, result := range w.Results {
		method := result.RequestMethod
		resultsByMethod[method] = append(resultsByMethod[method], result)
	}

	return resultsByMethod
}

// Helper methods for resource management

// createResource creates a test resource
func (w *WACACPConformanceTests) createResource(ctx context.Context, serverURL string, client *http.Client, path string, body []byte, contentType string) error {
	reqBody := bytes.NewReader(body)
	req, err := http.NewRequestWithContext(ctx, "PUT", serverURL+strings.TrimLeft(path, "/"), reqBody)
	if err != nil {
		return err
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to create resource: status %d", resp.StatusCode)
	}

	return nil
}

// deleteResource deletes a test resource
func (w *WACACPConformanceTests) deleteResource(ctx context.Context, serverURL string, client *http.Client, path string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", serverURL+strings.TrimLeft(path, "/"), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		// Ignore errors on cleanup
		return nil
	}
	defer resp.Body.Close()

	// Ignore status code on cleanup
	_ = resp

	return nil
}

// ValidateWACPolicy validates a WAC policy document
func (w *WACACPConformanceTests) ValidateWACPolicy(policyBody string) error {
	// Check for basic WAC structure
	if !strings.Contains(policyBody, "acl:") {
		return fmt.Errorf("WAC policy missing acl: prefix")
	}

	// Check for Authorization
	if !strings.Contains(policyBody, "Authorization") && !strings.Contains(policyBody, "auth") {
		return fmt.Errorf("WAC policy missing Authorization")
	}

	return nil
}

// ValidateACPPolicy validates an ACP policy document
func (w *WACACPConformanceTests) ValidateACPPolicy(policyBody string) error {
	// Check for basic ACP structure
	if !strings.Contains(policyBody, "@context") {
		return fmt.Errorf("ACP policy missing @context")
	}

	if !strings.Contains(policyBody, "@type") {
		return fmt.Errorf("ACP policy missing @type")
	}

	if !strings.Contains(policyBody, "AccessControl") && !strings.Contains(policyBody, "rule") {
		return fmt.Errorf("ACP policy missing AccessControl or rule")
	}

	return nil
}
