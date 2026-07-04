// Package authz provides tests for CSS comparison harness for fixture distribution transports
package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestNewCSSComparisonTransportReport tests report creation
func TestNewCSSComparisonTransportReport(t *testing.T) {
	report := newCSSComparisonTransportReport()

	if report.ReportID == "" {
		t.Error("ReportID should not be empty")
	}

	if report.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}

	if len(report.Results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(report.Results))
	}

	if report.TotalComparisons != 0 {
		t.Errorf("Expected 0 total comparisons, got %d", report.TotalComparisons)
	}
}

// TestCSSComparisonTransportReport_AddResult tests adding results to report
func TestCSSComparisonTransportReport_AddResult(t *testing.T) {
	report := newCSSComparisonTransportReport()

	// Add a matching result
	matchingResult := CSSComparisonTransportResult{
		ComparisonID:    "test-1",
		TransportType:   TransportMethodHTTP,
		Operation:       "distribute",
		Match:           true,
		Score:           1.0,
		Timestamp:       time.Now(),
		PayloadSize:     1024,
		CSSDuration:     100 * time.Millisecond,
		SidecarDuration: 150 * time.Millisecond,
	}

	report.AddResult(matchingResult)

	if report.TotalComparisons != 1 {
		t.Errorf("Expected 1 total comparison, got %d", report.TotalComparisons)
	}

	if report.MatchCount != 1 {
		t.Errorf("Expected 1 match, got %d", report.MatchCount)
	}

	if report.MismatchCount != 0 {
		t.Errorf("Expected 0 mismatches, got %d", report.MismatchCount)
	}

	// Add a mismatched result
	mismatchedResult := CSSComparisonTransportResult{
		ComparisonID:    "test-2",
		TransportType:   TransportMethodS3,
		Operation:       "distribute",
		Match:           false,
		Score:           0.5,
		Timestamp:       time.Now(),
		PayloadSize:     2048,
		Diffs:           []string{"status code mismatch"},
		CSSDuration:     200 * time.Millisecond,
		SidecarDuration: 250 * time.Millisecond,
	}

	report.AddResult(mismatchedResult)

	if report.TotalComparisons != 2 {
		t.Errorf("Expected 2 total comparisons, got %d", report.TotalComparisons)
	}

	if report.MatchCount != 1 {
		t.Errorf("Expected 1 match, got %d", report.MatchCount)
	}

	if report.MismatchCount != 1 {
		t.Errorf("Expected 1 mismatch, got %d", report.MismatchCount)
	}

	// Check by transport stats
	if len(report.ByTransport) != 2 {
		t.Errorf("Expected 2 transport types, got %d", len(report.ByTransport))
	}

	// Check HTTP transport stats
	httpStats, exists := report.ByTransport[TransportMethodHTTP]
	if !exists {
		t.Error("Expected HTTP transport stats")
	} else {
		if httpStats.Total != 1 {
			t.Errorf("Expected 1 HTTP total, got %d", httpStats.Total)
		}
		if httpStats.Matches != 1 {
			t.Errorf("Expected 1 HTTP match, got %d", httpStats.Matches)
		}
	}

	// Check S3 transport stats
	s3Stats, exists := report.ByTransport[TransportMethodS3]
	if !exists {
		t.Error("Expected S3 transport stats")
	} else {
		if s3Stats.Total != 1 {
			t.Errorf("Expected 1 S3 total, got %d", s3Stats.Total)
		}
		if s3Stats.Mismatches != 1 {
			t.Errorf("Expected 1 S3 mismatch, got %d", s3Stats.Mismatches)
		}
	}
}

// TestCSSComparisonTransportReport_Finalize tests report finalization
func TestCSSComparisonTransportReport_Finalize(t *testing.T) {
	report := newCSSComparisonTransportReport()

	// Add some results
	report.AddResult(CSSComparisonTransportResult{
		ComparisonID:    "test-1",
		TransportType:   TransportMethodHTTP,
		Match:           true,
		CSSDuration:     100 * time.Millisecond,
		SidecarDuration: 150 * time.Millisecond,
	})

	report.AddResult(CSSComparisonTransportResult{
		ComparisonID:    "test-2",
		TransportType:   TransportMethodHTTP,
		Match:           true,
		CSSDuration:     200 * time.Millisecond,
		SidecarDuration: 250 * time.Millisecond,
	})

	report.AddResult(CSSComparisonTransportResult{
		ComparisonID:    "test-3",
		TransportType:   TransportMethodHTTP,
		Match:           false,
		CSSDuration:     150 * time.Millisecond,
		SidecarDuration: 200 * time.Millisecond,
	})

	report.Finalize()

	// Check match rate
	expectedMatchRate := 2.0 / 3.0
	if report.MatchRate != expectedMatchRate {
		t.Errorf("Expected match rate %f, got %f", expectedMatchRate, report.MatchRate)
	}

	// Check average durations
	expectedAvgCSS := time.Duration((100 + 200 + 150) / 3 * int(time.Millisecond))
	if report.AvgCSSDuration != expectedAvgCSS {
		t.Errorf("Expected avg CSS duration %v, got %v", expectedAvgCSS, report.AvgCSSDuration)
	}

	expectedAvgSidecar := time.Duration((150 + 250 + 200) / 3 * int(time.Millisecond))
	if report.AvgSidecarDuration != expectedAvgSidecar {
		t.Errorf("Expected avg sidecar duration %v, got %v", expectedAvgSidecar, report.AvgSidecarDuration)
	}

	// Check HTTP transport stats
	httpStats, exists := report.ByTransport[TransportMethodHTTP]
	if !exists {
		t.Fatal("Expected HTTP transport stats")
	}

	if httpStats.MatchRate != expectedMatchRate {
		t.Errorf("Expected HTTP match rate %f, got %f", expectedMatchRate, httpStats.MatchRate)
	}
}

// TestCSSComparisonTransportReport_Export tests JSON export
func TestCSSComparisonTransportReport_Export(t *testing.T) {
	report := newCSSComparisonTransportReport()
	report.Environment = "test"

	// Add a result
	report.AddResult(CSSComparisonTransportResult{
		ComparisonID:    "test-1",
		TransportType:   TransportMethodLocal,
		Match:           true,
		Score:           1.0,
		Timestamp:       time.Now(),
		PayloadSize:     1024,
		CSSDuration:     100 * time.Millisecond,
		SidecarDuration: 150 * time.Millisecond,
	})

	// Export to JSON
	data, err := report.ExportReportToJSON()
	if err != nil {
		t.Fatalf("Failed to export report: %v", err)
	}

	// Verify it's valid JSON
	var parsedReport CSSComparisonTransportReport
	if err := json.Unmarshal(data, &parsedReport); err != nil {
		t.Fatalf("Failed to parse exported JSON: %v", err)
	}

	if parsedReport.Environment != "test" {
		t.Errorf("Expected environment 'test', got '%s'", parsedReport.Environment)
	}

	if len(parsedReport.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(parsedReport.Results))
	}

	if parsedReport.Results[0].TransportType != TransportMethodLocal {
		t.Errorf("Expected transport type %s, got %s", TransportMethodLocal, parsedReport.Results[0].TransportType)
	}
}

// TestDefaultCSSClient tests the CSS client
func TestDefaultCSSClient(t *testing.T) {
	// Create client
	client := NewDefaultCSSClient("http://localhost:3000")

	if client == nil {
		t.Fatal("Client should not be nil")
	}

	if client.baseURL != "http://localhost:3000" {
		t.Errorf("Expected base URL 'http://localhost:3000', got '%s'", client.baseURL)
	}

	if client.client == nil {
		t.Error("HTTP client should not be nil")
	}

	// Test with token
	clientWithToken := NewDefaultCSSClientWithToken("http://localhost:3000", "test-token")
	if clientWithToken.accessToken != "test-token" {
		t.Errorf("Expected access token 'test-token', got '%s'", clientWithToken.accessToken)
	}
}

// TestDefaultCSSClientWithToken tests client with token
func TestDefaultCSSClientWithToken(t *testing.T) {
	client := NewDefaultCSSClientWithToken("http://localhost:3000", "dpop-token")

	if client == nil {
		t.Fatal("Client should not be nil")
	}

	if client.accessToken != "dpop-token" {
		t.Errorf("Expected access token 'dpop-token', got '%s'", client.accessToken)
	}
}

// TestNewCSSTransportComparator tests comparator creation
func TestNewCSSTransportComparator(t *testing.T) {
	cssClient := NewDefaultCSSClient("http://localhost:3000")
	sidecarClient := NewDefaultCSSClient("http://localhost:8443")

	comparator := NewCSSTransportComparator(cssClient, sidecarClient)

	if comparator == nil {
		t.Fatal("Comparator should not be nil")
	}

	if comparator.cssClient == nil {
		t.Error("CSS client should not be nil")
	}

	if comparator.sidecarClient == nil {
		t.Error("Sidecar client should not be nil")
	}

	if !comparator.compareHeaders {
		t.Error("Header comparison should be enabled by default")
	}

	if comparator.compareBody {
		t.Error("Body comparison should be disabled by default")
	}

	if comparator.report == nil {
		t.Error("Report should not be nil")
	}
}

// TestCSSTransportComparator_WithOptions tests comparator options
func TestCSSTransportComparator_WithOptions(t *testing.T) {
	cssClient := NewDefaultCSSClient("http://localhost:3000")
	sidecarClient := NewDefaultCSSClient("http://localhost:8443")

	// Create with options
	comparator := NewCSSTransportComparator(
		cssClient,
		sidecarClient,
		WithHeaderComparison(false),
		WithBodyComparison(true),
	)

	if comparator.compareHeaders {
		t.Error("Header comparison should be disabled")
	}

	if !comparator.compareBody {
		t.Error("Body comparison should be enabled")
	}
}

// TestCSSTransportComparator_ResetReport tests report reset
func TestCSSTransportComparator_ResetReport(t *testing.T) {
	cssClient := NewDefaultCSSClient("http://localhost:3000")
	sidecarClient := NewDefaultCSSClient("http://localhost:8443")

	comparator := NewCSSTransportComparator(cssClient, sidecarClient)

	// Add a result to the report
	comparator.report.AddResult(CSSComparisonTransportResult{
		ComparisonID: "test-1",
		Match:        true,
	})

	if comparator.report.TotalComparisons != 1 {
		t.Errorf("Expected 1 comparison, got %d", comparator.report.TotalComparisons)
	}

	// Reset the report
	comparator.ResetReport()

	if comparator.report.TotalComparisons != 0 {
		t.Errorf("Expected 0 comparisons after reset, got %d", comparator.report.TotalComparisons)
	}
}

// TestCSSTransportComparator_GetReport tests getting report
func TestCSSTransportComparator_GetReport(t *testing.T) {
	cssClient := NewDefaultCSSClient("http://localhost:3000")
	sidecarClient := NewDefaultCSSClient("http://localhost:8443")

	comparator := NewCSSTransportComparator(cssClient, sidecarClient)

	// Add results
	comparator.report.AddResult(CSSComparisonTransportResult{
		ComparisonID:    "test-1",
		TransportType:   TransportMethodHTTP,
		Match:           true,
		CSSDuration:     100 * time.Millisecond,
		SidecarDuration: 150 * time.Millisecond,
	})

	comparator.report.AddResult(CSSComparisonTransportResult{
		ComparisonID:    "test-2",
		TransportType:   TransportMethodHTTP,
		Match:           true,
		CSSDuration:     200 * time.Millisecond,
		SidecarDuration: 250 * time.Millisecond,
	})

	// Get report (should finalize it)
	report := comparator.GetReport()

	if report == nil {
		t.Fatal("Report should not be nil")
	}

	// Check that it's finalized
	if report.MatchRate == 0 {
		t.Error("Match rate should be calculated after finalization")
	}

	if report.AvgCSSDuration == 0 {
		t.Error("Average CSS duration should be calculated")
	}
}

// TestNewCSSComparisonTransportHarness tests harness creation
func TestNewCSSComparisonTransportHarness(t *testing.T) {
	cssClient := NewDefaultCSSClient("http://localhost:3000")
	sidecarClient := NewDefaultCSSClient("http://localhost:8443")

	harness := NewCSSComparisonTransportHarness(cssClient, sidecarClient)

	if harness == nil {
		t.Fatal("Harness should not be nil")
	}

	if harness.comparator == nil {
		t.Error("Comparator should not be nil")
	}
}

// TestTransportCompareOperation tests transport compare operation struct
func TestTransportCompareOperation(t *testing.T) {
	op := TransportCompareOperation{
		Job: FixtureDistributionJob{
			DistributionID: "test-dist",
			CatalogHash:    "test-hash",
			BundleHashes:   []string{"hash1", "hash2"},
		},
		Target: FixtureDistributionTarget{
			ID:     "test-target",
			URL:    "http://localhost:3000/fixture",
			Method: DistributionMethodHTTPS,
		},
		Payload: []byte("test payload"),
	}

	if op.Job.DistributionID != "test-dist" {
		t.Errorf("Expected distribution ID 'test-dist', got '%s'", op.Job.DistributionID)
	}

	if op.Target.Method != DistributionMethodHTTPS {
		t.Errorf("Expected method %s, got %s", TransportMethodHTTP, op.Target.Method)
	}

	if string(op.Payload) != "test payload" {
		t.Errorf("Expected payload 'test payload', got '%s'", string(op.Payload))
	}
}

// TestCompareResults tests the compareResults function
func TestCompareResults(t *testing.T) {
	cssClient := NewDefaultCSSClient("http://localhost:3000")
	sidecarClient := NewDefaultCSSClient("http://localhost:8443")

	comparator := NewCSSTransportComparator(cssClient, sidecarClient)

	// Test 1: Both success, same status, no header/body comparison
	cssResult := TransportResult{
		Success: true,
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/turtle"}},
		Body:    []byte("test"),
	}

	sidecarResult := TransportResult{
		Success: true,
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/turtle"}},
		Body:    []byte("test"),
	}

	match, diffs, score := comparator.compareResults(cssResult, sidecarResult)

	if !match {
		t.Error("Results should match")
	}

	if len(diffs) != 0 {
		t.Errorf("Expected no diffs, got %v", diffs)
	}

	if score != 1.0 {
		t.Errorf("Expected score 1.0, got %f", score)
	}

	// Test 2: Different success status
	cssResult2 := TransportResult{
		Success: true,
		Status:  http.StatusOK,
	}

	sidecarResult2 := TransportResult{
		Success: false,
		Status:  http.StatusInternalServerError,
		Error:   "internal error",
	}

	match2, diffs2, score2 := comparator.compareResults(cssResult2, sidecarResult2)

	if match2 {
		t.Error("Results should not match (different success)")
	}

	if len(diffs2) == 0 {
		t.Error("Expected diffs for success mismatch")
	}

	if score2 > 0.6 {
		t.Errorf("Expected score <= 0.6 for success mismatch, got %f", score2)
	}

	// Test 3: Both failed with same error
	cssResult3 := TransportResult{
		Success: false,
		Status:  http.StatusNotFound,
		Error:   "not found",
	}

	sidecarResult3 := TransportResult{
		Success: false,
		Status:  http.StatusNotFound,
		Error:   "not found",
	}

	match3, diffs3, score3 := comparator.compareResults(cssResult3, sidecarResult3)

	// Both failed with same error - should match
	if !match3 {
		t.Error("Both failures with same error should match")
	}

	if len(diffs3) != 0 {
		t.Errorf("Expected no diffs for matching failures, got %v", diffs3)
	}

	if score3 <= 0.5 {
		t.Errorf("Expected reasonable score for matching failures, got %f", score3)
	}

	// Test 4: Different status codes
	cssResult4 := TransportResult{
		Success: true,
		Status:  http.StatusOK,
	}

	sidecarResult4 := TransportResult{
		Success: true,
		Status:  http.StatusCreated,
	}

	match4, diffs4, score4 := comparator.compareResults(cssResult4, sidecarResult4)

	if match4 {
		t.Error("Different status codes should not match")
	}

	if len(diffs4) == 0 {
		t.Error("Expected diffs for status code mismatch")
	}

	if score4 >= 0.8 {
		t.Errorf("Expected score < 0.8 for status code mismatch, got %f", score4)
	}
}

// TestIsExpectedSidecarHeader tests expected header detection
func TestIsExpectedSidecarHeader(t *testing.T) {
	tests := []struct {
		header   string
		expected bool
	}{
		{"Via", true},
		{"X-Forwarded-For", true},
		{"X-Forwarded-Host", true},
		{"X-Forwarded-Proto", true},
		{"X-Request-Id", true},
		{"X-Correlation-Id", true},
		{"X-Sidecar-Version", true},
		{"Content-Type", false},
		{"Authorization", false},
		{"Accept", false},
	}

	for _, test := range tests {
		result := isExpectedSidecarHeader(test.header)
		if result != test.expected {
			t.Errorf("isExpectedSidecarHeader(%q) = %v, expected %v", test.header, result, test.expected)
		}
	}
}

// TestIsExpectedHeaderModification tests expected header modification detection
func TestIsExpectedHeaderModification(t *testing.T) {
	tests := []struct {
		header       string
		cssValue     string
		sidecarValue string
		expected     bool
	}{
		{"Content-Length", "100", "105", true},
		{"Date", "Mon, 01 Jan 2024 00:00:00 GMT", "Mon, 01 Jan 2024 00:00:01 GMT", true},
		{"Server", "Community Solid Server", "solid-sidecar", true},
		{"Content-Type", "text/turtle", "text/turtle", false},
		{"ETag", "abc123", "def456", false},
	}

	for _, test := range tests {
		result := isExpectedHeaderModification(test.header, test.cssValue, test.sidecarValue)
		if result != test.expected {
			t.Errorf("isExpectedHeaderModification(%q, %q, %q) = %v, expected %v",
				test.header, test.cssValue, test.sidecarValue, result, test.expected)
		}
	}
}

// TestTransportComparisonStats tests transport stats struct
func TestTransportComparisonStats(t *testing.T) {
	stats := &TransportComparisonStats{
		TransportType: TransportMethodHTTP,
		Total:         10,
		Matches:       8,
		Mismatches:    2,
		CommonDiffs:   make(map[string]int),
	}

	stats.CommonDiffs["diff1"] = 1
	stats.CommonDiffs["diff2"] = 1

	if stats.MatchRate != 0 {
		// Match rate not calculated yet
		t.Log("Match rate not calculated yet (expected)")
	}

	// After finalization (in report), match rate would be 0.8
}

// BenchmarkCSSComparisonTransport tests performance of comparison
func BenchmarkCSSComparisonTransport(b *testing.B) {
	cssClient := NewDefaultCSSClient("http://localhost:3000")
	sidecarClient := NewDefaultCSSClient("http://localhost:8443")

	comparator := NewCSSTransportComparator(cssClient, sidecarClient)

	// Create test data
	job := FixtureDistributionJob{
		DistributionID: "benchmark-dist",
		CatalogHash:    "benchmark-hash",
		BundleHashes:   []string{"hash1"},
	}

	target := FixtureDistributionTarget{
		ID:     "benchmark-target",
		URL:    "http://localhost:3000/fixture",
		Method: DistributionMethodLocalFile,
	}

	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Reset report for each iteration
		comparator.ResetReport()

		// Run comparison
		_ = comparator.CompareFixtureDistribution(
			context.Background(),
			job,
			target,
			payload,
		)
	}
}

// BenchmarkCSSComparisonReportExport tests performance of report export
func BenchmarkCSSComparisonReportExport(b *testing.B) {
	report := newCSSComparisonTransportReport()

	// Add many results
	for i := 0; i < 1000; i++ {
		report.AddResult(CSSComparisonTransportResult{
			ComparisonID:    fmt.Sprintf("test-%d", i),
			TransportType:   TransportMethodHTTP,
			Match:           true,
			CSSDuration:     time.Duration(i%100) * time.Millisecond,
			SidecarDuration: time.Duration((i+1)%100) * time.Millisecond,
		})
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Clone report for each iteration
		clonedReport := *report
		_, _ = clonedReport.ExportReportToJSON()
	}
}
