// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements Range and compression compatibility tests.
package conformance

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RangeCompressionConformanceTests implements conformance tests for Range requests
// and compression support as required by Phase 20.
type RangeCompressionConformanceTests struct {
	config *TestConfig
}

// NewRangeCompressionConformanceTests creates a new Range and compression conformance test suite
func NewRangeCompressionConformanceTests() *RangeCompressionConformanceTests {
	return &RangeCompressionConformanceTests{
		config: NewTestConfig(),
	}
}

// Run executes all Range and compression conformance tests
func (r *RangeCompressionConformanceTests) Run(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult {
	results := make([]ConformanceTestResult, 0)

	// Range request tests
	results = append(results, r.runRangeTests(ctx, serverURL, client)...)

	// Compression tests
	results = append(results, r.runCompressionTests(ctx, serverURL, client)...)

	return results
}

// GetConformanceScore returns the conformance score for this test suite
func (r *RangeCompressionConformanceTests) GetConformanceScore() float64 {
	// This would be calculated based on test results
	// For now, return 0 as it's calculated after running tests
	return 0
}

// runRangeTests executes Range request conformance tests
func (r *RangeCompressionConformanceTests) runRangeTests(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult {
	results := make([]ConformanceTestResult, 0)

	// Test 1: Range request with valid range
	startTime := time.Now()
	testResult := ConformanceTestResult{
		TestID:          "range-001",
		TestName:        "Range request with valid range",
		TestCategory:    "Range Requests",
		TestDescription: "Server should support Range requests and return 206 Partial Content",
		TestStatus:      TestStatusFailed,
		StartTime:       startTime.Format(time.RFC3339),
		Severity:        SeverityHigh,
		SolidSpecRef:    "https://solidproject.org/TR/protocol#range-requests",
	}

	// Create a test resource with known content
	testContent := []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	testResourceURL := fmt.Sprintf("%s/test-range-resource", serverURL)

	// Put the test resource
	putReq, _ := http.NewRequestWithContext(ctx, MethodPUT, testResourceURL, bytes.NewReader(testContent))
	putReq.Header.Set("Content-Type", "text/plain")
	putResp, putErr := client.Do(putReq)
	if putErr != nil || putResp.StatusCode != http.StatusCreated && putResp.StatusCode != http.StatusNoContent && putResp.StatusCode != http.StatusOK {
		testResult.ErrorMessage = "Failed to create test resource for range testing"
		if putErr != nil {
			testResult.ErrorDetails = putErr.Error()
		} else if putResp != nil {
			testResult.ErrorDetails = fmt.Sprintf("Status: %d", putResp.StatusCode)
		}
		testResult.EndTime = time.Now().Format(time.RFC3339)
		testResult.DurationMs = int64(time.Since(startTime).Milliseconds())
		results = append(results, testResult)
		return results
	}

	// Close the put response body
	if putResp != nil && putResp.Body != nil {
		io.Copy(io.Discard, putResp.Body)
		putResp.Body.Close()
	}

	// Test range request for bytes 0-9
	req, _ := http.NewRequestWithContext(ctx, MethodGET, testResourceURL, nil)
	req.Header.Set("Range", "bytes=0-9")

	resp, err := client.Do(req)
	testResult.EndTime = time.Now().Format(time.RFC3339)
	testResult.DurationMs = int64(time.Since(startTime).Milliseconds())

	if err != nil {
		testResult.ErrorMessage = fmt.Sprintf("Range request failed: %v", err)
		results = append(results, testResult)
		return results
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	if resp.StatusCode == http.StatusPartialContent {
		contentRange := resp.Header.Get("Content-Range")
		if contentRange == "" {
			testResult.ErrorMessage = "Missing Content-Range header in 206 response"
			results = append(results, testResult)
			return results
		}

		body, _ := io.ReadAll(resp.Body)
		expected := "0123456789"
		if string(body) == expected {
			testResult.TestStatus = TestStatusPassed
			testResult.Expectation = "Server returns 206 Partial Content with correct body and Content-Range header"
			testResult.ActualResult = fmt.Sprintf("Returned %d bytes: %s", len(body), string(body))
		} else {
			testResult.ErrorMessage = fmt.Sprintf("Range body mismatch. Expected: %s, Got: %s", expected, string(body))
		}
	} else if resp.StatusCode == http.StatusOK {
		// Server doesn't support range requests, which is acceptable
		testResult.TestStatus = TestStatusSkipped
		testResult.Expectation = "Server supports Range requests"
		testResult.ActualResult = "Server does not support Range requests (returned 200 OK instead of 206)"
	} else {
		testResult.ErrorMessage = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
	}

	results = append(results, testResult)

	// Test 2: Range request with unsatisfiable range
	startTime = time.Now()
	testResult = ConformanceTestResult{
		TestID:          "range-002",
		TestName:        "Range request with unsatisfiable range",
		TestCategory:    "Range Requests",
		TestDescription: "Server should return 416 Range Not Satisfiable for invalid ranges",
		TestStatus:      TestStatusFailed,
		StartTime:       startTime.Format(time.RFC3339),
		Severity:        SeverityMedium,
		SolidSpecRef:    "https://solidproject.org/TR/protocol#range-requests",
	}

	req, _ = http.NewRequestWithContext(ctx, MethodGET, testResourceURL, nil)
	req.Header.Set("Range", "bytes=100-200") // Beyond the content length

	resp, err = client.Do(req)
	testResult.EndTime = time.Now().Format(time.RFC3339)
	testResult.DurationMs = int64(time.Since(startTime).Milliseconds())

	if err != nil {
		testResult.ErrorMessage = fmt.Sprintf("Request failed: %v", err)
		results = append(results, testResult)
		return results
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		contentRange := resp.Header.Get("Content-Range")
		if contentRange != "" {
			testResult.TestStatus = TestStatusPassed
			testResult.Expectation = "Server returns 416 Range Not Satisfiable with Content-Range header"
			testResult.ActualResult = fmt.Sprintf("Status: %d, Content-Range: %s", resp.StatusCode, contentRange)
		} else {
			testResult.ErrorMessage = "Missing Content-Range header in 416 response"
		}
	} else {
		// Range requests not supported or different behavior
		testResult.TestStatus = TestStatusSkipped
		testResult.Expectation = "Server returns 416 Range Not Satisfiable"
		testResult.ActualResult = fmt.Sprintf("Server returned %d", resp.StatusCode)
	}

	results = append(results, testResult)

	// Test 3: Range request with multiple ranges (if supported)
	startTime = time.Now()
	testResult = ConformanceTestResult{
		TestID:          "range-003",
		TestName:        "Range request with multiple ranges",
		TestCategory:    "Range Requests",
		TestDescription: "Server should handle multiple range requests if supported",
		TestStatus:      TestStatusFailed,
		StartTime:       startTime.Format(time.RFC3339),
		Severity:        SeverityLow,
		SolidSpecRef:    "https://solidproject.org/TR/protocol#range-requests",
	}

	req, _ = http.NewRequestWithContext(ctx, MethodGET, testResourceURL, nil)
	req.Header.Set("Range", "bytes=0-5,10-15")

	resp, err = client.Do(req)
	testResult.EndTime = time.Now().Format(time.RFC3339)
	testResult.DurationMs = int64(time.Since(startTime).Milliseconds())

	if err != nil {
		testResult.ErrorMessage = fmt.Sprintf("Request failed: %v", err)
		results = append(results, testResult)
		return results
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	// Multiple ranges may or may not be supported
	if resp.StatusCode == http.StatusPartialContent || resp.StatusCode == http.StatusOK {
		testResult.TestStatus = TestStatusPassed
		testResult.Expectation = "Server handles or gracefully ignores multiple range requests"
		testResult.ActualResult = fmt.Sprintf("Status: %d", resp.StatusCode)
	} else {
		testResult.TestStatus = TestStatusSkipped
		testResult.ActualResult = fmt.Sprintf("Server returned %d for multiple ranges", resp.StatusCode)
	}

	results = append(results, testResult)

	// Cleanup: Delete the test resource
	deleteReq, _ := http.NewRequestWithContext(ctx, MethodDELETE, testResourceURL, nil)
	deleteResp, _ := client.Do(deleteReq)
	if deleteResp != nil && deleteResp.Body != nil {
		io.Copy(io.Discard, deleteResp.Body)
		deleteResp.Body.Close()
	}

	return results
}

// runCompressionTests executes compression conformance tests
func (r *RangeCompressionConformanceTests) runCompressionTests(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult {
	results := make([]ConformanceTestResult, 0)

	// Test 1: Server accepts gzip compression
	startTime := time.Now()
	testResult := ConformanceTestResult{
		TestID:          "compression-001",
		TestName:        "Server accepts gzip compression",
		TestCategory:    "Compression",
		TestDescription: "Server should accept and respond with gzip-compressed responses",
		TestStatus:      TestStatusFailed,
		StartTime:       startTime.Format(time.RFC3339),
		Severity:        SeverityHigh,
		SolidSpecRef:    "https://solidproject.org/TR/protocol#content-encoding",
	}

	// Create a larger test resource for compression
	// Generate random content to ensure it doesn't compress to the same size
	testContent := make([]byte, 1024)
	_, err := rand.Read(testContent)
	if err != nil {
		testResult.ErrorMessage = fmt.Sprintf("Failed to generate random content: %v", err)
		testResult.EndTime = time.Now().Format(time.RFC3339)
		testResult.DurationMs = int64(time.Since(startTime).Milliseconds())
		results = append(results, testResult)
		return results
	}

	testResourceURL := fmt.Sprintf("%s/test-compression-resource", serverURL)

	// Put the test resource
	putReq, _ := http.NewRequestWithContext(ctx, MethodPUT, testResourceURL, bytes.NewReader(testContent))
	putReq.Header.Set("Content-Type", "application/octet-stream")
	putResp, putErr := client.Do(putReq)
	if putErr != nil || (putResp.StatusCode != http.StatusCreated && putResp.StatusCode != http.StatusNoContent && putResp.StatusCode != http.StatusOK) {
		testResult.ErrorMessage = "Failed to create test resource for compression testing"
		if putErr != nil {
			testResult.ErrorDetails = putErr.Error()
		} else if putResp != nil {
			testResult.ErrorDetails = fmt.Sprintf("Status: %d", putResp.StatusCode)
		}
		testResult.EndTime = time.Now().Format(time.RFC3339)
		testResult.DurationMs = int64(time.Since(startTime).Milliseconds())
		results = append(results, testResult)
		return results
	}

	// Close the put response body
	if putResp != nil && putResp.Body != nil {
		io.Copy(io.Discard, putResp.Body)
		putResp.Body.Close()
	}

	// Request with Accept-Encoding: gzip
	req, _ := http.NewRequestWithContext(ctx, MethodGET, testResourceURL, nil)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	testResult.EndTime = time.Now().Format(time.RFC3339)
	testResult.DurationMs = int64(time.Since(startTime).Milliseconds())

	if err != nil {
		testResult.ErrorMessage = fmt.Sprintf("Compressed request failed: %v", err)
		results = append(results, testResult)
		return results
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	// Check if response is compressed
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding == "gzip" {
		// Verify we can decompress the body
		body, _ := io.ReadAll(resp.Body)
		gzipReader, gzipErr := gzip.NewReader(bytes.NewReader(body))
		if gzipErr != nil {
			testResult.ErrorMessage = fmt.Sprintf("Response has gzip Content-Encoding but body is not gzip: %v", gzipErr)
			results = append(results, testResult)
			return results
		}
		defer gzipReader.Close()

		decompressed, _ := io.ReadAll(gzipReader)
		if len(decompressed) == len(testContent) {
			testResult.TestStatus = TestStatusPassed
			testResult.Expectation = "Server accepts gzip compression and returns gzip-compressed responses"
			testResult.ActualResult = fmt.Sprintf("Compressed response with Content-Encoding: %s, Original size: %d, Compressed size: %d",
				contentEncoding, len(testContent), len(body))
		} else {
			testResult.ErrorMessage = fmt.Sprintf("Decompressed size mismatch. Expected: %d, Got: %d", len(testContent), len(decompressed))
		}
	} else if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotModified {
		// Server returned uncompressed response (which is acceptable)
		testResult.TestStatus = TestStatusSkipped
		testResult.Expectation = "Server supports gzip compression"
		testResult.ActualResult = "Server does not compress responses (no Content-Encoding header)"
	} else {
		testResult.ErrorMessage = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
	}

	results = append(results, testResult)

	// Test 2: Server advertises compression support via Accept-Encoding
	startTime = time.Now()
	testResult = ConformanceTestResult{
		TestID:          "compression-002",
		TestName:        "Server advertises compression in response",
		TestCategory:    "Compression",
		TestDescription: "Server should include Vary: Accept-Encoding header to indicate compression support",
		TestStatus:      TestStatusFailed,
		StartTime:       startTime.Format(time.RFC3339),
		Severity:        SeverityMedium,
		SolidSpecRef:    "https://solidproject.org/TR/protocol#content-encoding",
	}

	// Make a request without Accept-Encoding to see if Vary header is present
	req, _ = http.NewRequestWithContext(ctx, MethodGET, testResourceURL, nil)
	resp, err = client.Do(req)
	testResult.EndTime = time.Now().Format(time.RFC3339)
	testResult.DurationMs = int64(time.Since(startTime).Milliseconds())

	if err != nil {
		testResult.ErrorMessage = fmt.Sprintf("Request failed: %v", err)
		results = append(results, testResult)
		return results
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	varyHeader := resp.Header.Get("Vary")
	if strings.Contains(varyHeader, "Accept-Encoding") {
		testResult.TestStatus = TestStatusPassed
		testResult.Expectation = "Server includes Vary: Accept-Encoding header"
		testResult.ActualResult = fmt.Sprintf("Vary header: %s", varyHeader)
	} else {
		// Check if server compresses anyway (some do without Vary)
		contentEncoding := resp.Header.Get("Content-Encoding")
		if contentEncoding == "gzip" {
			testResult.TestStatus = TestStatusPassed
			testResult.Expectation = "Server compresses responses (Vary header optional)"
			testResult.ActualResult = fmt.Sprintf("Content-Encoding: %s, Vary: %s", contentEncoding, varyHeader)
		} else {
			testResult.TestStatus = TestStatusSkipped
			testResult.Expectation = "Server advertises compression support via Vary header"
			testResult.ActualResult = fmt.Sprintf("No Vary: Accept-Encoding header found. Vary: %s", varyHeader)
		}
	}

	results = append(results, testResult)

	// Test 3: Compression with br (Brotli) - if supported
	startTime = time.Now()
	testResult = ConformanceTestResult{
		TestID:          "compression-003",
		TestName:        "Server accepts br compression",
		TestCategory:    "Compression",
		TestDescription: "Server may support Brotli compression (optional)",
		TestStatus:      TestStatusFailed,
		StartTime:       startTime.Format(time.RFC3339),
		Severity:        SeverityLow,
		SolidSpecRef:    "https://solidproject.org/TR/protocol#content-encoding",
	}

	req, _ = http.NewRequestWithContext(ctx, MethodGET, testResourceURL, nil)
	req.Header.Set("Accept-Encoding", "br, gzip")

	resp, err = client.Do(req)
	testResult.EndTime = time.Now().Format(time.RFC3339)
	testResult.DurationMs = int64(time.Since(startTime).Milliseconds())

	if err != nil {
		testResult.ErrorMessage = fmt.Sprintf("Request failed: %v", err)
		results = append(results, testResult)
		return results
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	contentEncoding = resp.Header.Get("Content-Encoding")
	if contentEncoding == "br" {
		testResult.TestStatus = TestStatusPassed
		testResult.Expectation = "Server supports Brotli compression"
		testResult.ActualResult = fmt.Sprintf("Content-Encoding: %s", contentEncoding)
	} else if contentEncoding == "gzip" {
		testResult.TestStatus = TestStatusPassed
		testResult.Expectation = "Server supports gzip compression (br not available)"
		testResult.ActualResult = fmt.Sprintf("Content-Encoding: %s (br not supported)", contentEncoding)
	} else {
		testResult.TestStatus = TestStatusSkipped
		testResult.Expectation = "Server supports br compression"
		testResult.ActualResult = "Server does not support br compression"
	}

	results = append(results, testResult)

	// Test 4: Content-Length header with compression
	startTime = time.Now()
	testResult = ConformanceTestResult{
		TestID:          "compression-004",
		TestName:        "Content-Length header with compression",
		TestCategory:    "Compression",
		TestDescription: "Server should provide Content-Length for compressed responses",
		TestStatus:      TestStatusFailed,
		StartTime:       startTime.Format(time.RFC3339),
		Severity:        SeverityMedium,
		SolidSpecRef:    "https://solidproject.org/TR/protocol#content-encoding",
	}

	req, _ = http.NewRequestWithContext(ctx, MethodGET, testResourceURL, nil)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err = client.Do(req)
	testResult.EndTime = time.Now().Format(time.RFC3339)
	testResult.DurationMs = int64(time.Since(startTime).Milliseconds())

	if err != nil {
		testResult.ErrorMessage = fmt.Sprintf("Request failed: %v", err)
		results = append(results, testResult)
		return results
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	contentEncoding = resp.Header.Get("Content-Encoding")
	if contentEncoding == "gzip" {
		contentLength := resp.Header.Get("Content-Length")
		if contentLength != "" {
			testResult.TestStatus = TestStatusPassed
			testResult.Expectation = "Server provides Content-Length for compressed responses"
			testResult.ActualResult = fmt.Sprintf("Content-Encoding: %s, Content-Length: %s", contentEncoding, contentLength)
		} else {
			testResult.ErrorMessage = "Missing Content-Length header for compressed response"
		}
	} else {
		// No compression, check Content-Length for uncompressed
		contentLength := resp.Header.Get("Content-Length")
		if contentLength != "" {
			testResult.TestStatus = TestStatusPassed
			testResult.Expectation = "Server provides Content-Length for responses"
			testResult.ActualResult = fmt.Sprintf("Content-Length: %s (uncompressed)", contentLength)
		} else {
			testResult.TestStatus = TestStatusSkipped
			testResult.Expectation = "Server provides Content-Length for compressed responses"
			testResult.ActualResult = "No Content-Encoding header, no Content-Length requirement"
		}
	}

	results = append(results, testResult)

	// Cleanup: Delete the test resource
	deleteReq, _ := http.NewRequestWithContext(ctx, MethodDELETE, testResourceURL, nil)
	deleteResp, _ := client.Do(deleteReq)
	if deleteResp != nil && deleteResp.Body != nil {
		io.Copy(io.Discard, deleteResp.Body)
		deleteResp.Body.Close()
	}

	return results
}

// RangeCompressionReport generates a report for Range and compression tests
type RangeCompressionReport struct {
	TotalTests       int                     `json:"total_tests"`
	PassedTests      int                     `json:"passed_tests"`
	FailedTests      int                     `json:"failed_tests"`
	SkippedTests     int                     `json:"skipped_tests"`
	Score            float64                 `json:"score"`
	Tests            []ConformanceTestResult `json:"tests"`
	RangeTests       map[string]interface{}  `json:"range_tests"`
	CompressionTests map[string]interface{}  `json:"compression_tests"`
	Summary          string                  `json:"summary"`
}

// GenerateRangeCompressionReport creates a comprehensive report for Range and compression tests
func GenerateRangeCompressionReport(results []ConformanceTestResult) (*RangeCompressionReport, error) {
	report := &RangeCompressionReport{
		Tests:            results,
		RangeTests:       make(map[string]interface{}),
		CompressionTests: make(map[string]interface{}),
	}

	for _, result := range results {
		report.TotalTests++
		if result.TestStatus == TestStatusPassed {
			report.PassedTests++
		} else if result.TestStatus == TestStatusFailed || result.TestStatus == TestStatusError {
			report.FailedTests++
		} else if result.TestStatus == TestStatusSkipped {
			report.SkippedTests++
		}

		// Categorize tests
		if strings.Contains(result.TestID, "range") {
			report.RangeTests[result.TestID] = map[string]interface{}{
				"status":   result.TestStatus,
				"name":     result.TestName,
				"severity": result.Severity,
			}
		}
		if strings.Contains(result.TestID, "compression") {
			report.CompressionTests[result.TestID] = map[string]interface{}{
				"status":   result.TestStatus,
				"name":     result.TestName,
				"severity": result.Severity,
			}
		}
	}

	if report.TotalTests > 0 {
		report.Score = float64(report.PassedTests) / float64(report.TotalTests) * 100.0
	}

	// Generate summary
	var summary strings.Builder
	summary.WriteString("Range and Compression Compatibility Test Report\n")
	summary.WriteString(fmt.Sprintf("Total Tests: %d, Passed: %d, Failed: %d, Skipped: %d\n",
		report.TotalTests, report.PassedTests, report.FailedTests, report.SkippedTests))
	summary.WriteString(fmt.Sprintf("Score: %.2f%%\n", report.Score))

	report.Summary = summary.String()

	return report, nil
}

// CompressData is a utility function to compress data using gzip
func CompressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write(data)
	if err != nil {
		writer.Close()
		return nil, err
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GenerateRandomData generates random data for testing
func GenerateRandomData(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	return data, err
}

// ValidateGzipData validates that data is gzip compressed
func ValidateGzipData(data []byte) bool {
	// Gzip magic number: 0x1f 0x8b
	if len(data) < 2 {
		return false
	}
	return data[0] == 0x1f && data[1] == 0x8b
}

// GetCompressionSupport returns the compression algorithms supported by the server
func (r *RangeCompressionConformanceTests) GetCompressionSupport(ctx context.Context, serverURL string, client *http.Client) (map[string]bool, error) {
	support := make(map[string]bool)

	// Test gzip
	req, _ := http.NewRequestWithContext(ctx, MethodGET, serverURL, nil)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	if resp.Header.Get("Content-Encoding") == "gzip" {
		support["gzip"] = true
	}

	// Test br (Brotli)
	req, _ = http.NewRequestWithContext(ctx, MethodGET, serverURL, nil)
	req.Header.Set("Accept-Encoding", "br")

	resp, err = client.Do(req)
	if err != nil {
		// Don't return error, just mark as not supported
		_ = err
	} else {
		defer func() {
			if resp != nil && resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		if resp.Header.Get("Content-Encoding") == "br" {
			support["br"] = true
		}
	}

	return support, nil
}

// ExportResultsAsJSON exports test results as JSON for integration with other tools
func (r *RangeCompressionConformanceTests) ExportResultsAsJSON(results []ConformanceTestResult) (string, error) {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}
