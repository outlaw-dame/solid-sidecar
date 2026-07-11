// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file provides the main conformance suite runner that executes all conformance tests.
package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ConformanceSuite is the main suite that runs all conformance tests
type ConformanceSuite struct {
	// Configuration
	ServerURL   string
	HTTPClient  *http.Client
	Timeout     time.Duration
	StrictMode  bool
	DebugOutput bool

	// Results
	mu           sync.Mutex
	AllResults   []ConformanceTestResult
	SuiteResults map[string][]ConformanceTestResult
}

// NewConformanceSuite creates a new conformance test suite
func NewConformanceSuite(serverURL string) *ConformanceSuite {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &ConformanceSuite{
		ServerURL:    serverURL,
		HTTPClient:   client,
		Timeout:      30 * time.Second,
		StrictMode:   true,
		DebugOutput:  false,
		SuiteResults: make(map[string][]ConformanceTestResult),
		AllResults:   make([]ConformanceTestResult, 0),
	}
}

// RunAll executes all conformance test suites
func (s *ConformanceSuite) RunAll(ctx context.Context) error {
	fmt.Printf("Starting Solid Conformance Test Suite\n")
	fmt.Printf("Server URL: %s\n", s.ServerURL)
	fmt.Printf("Timeout: %v\n", s.Timeout)
	fmt.Printf("Strict Mode: %v\n\n", s.StrictMode)

	startTime := time.Now()

	// Run each suite
	suites := []struct {
		name string
		run  func(context.Context) []ConformanceTestResult
	}{
		{"Content Negotiation", func(ctx context.Context) []ConformanceTestResult {
			return NewContentNegotiationConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient)
		}},
		{"Conditional Requests", func(ctx context.Context) []ConformanceTestResult {
			return NewConditionalRequestConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient)
		}},
		{"HTTP Method Matrix", func(ctx context.Context) []ConformanceTestResult {
			return NewHTTPMethodMatrixConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient)
		}},
		{"Range and Compression", func(ctx context.Context) []ConformanceTestResult {
			return NewRangeCompressionConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient)
		}},
		{"Storage Description", func(ctx context.Context) []ConformanceTestResult {
			return NewStorageDescriptionConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient)
		}},
		{"WebID/OIDC/DPoP", func(ctx context.Context) []ConformanceTestResult {
			return NewWebIDOIDCDPoPConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient)
		}},
		{"WAC and ACP Fixtures", func(ctx context.Context) []ConformanceTestResult {
			return NewWACACPConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient)
		}},
		{"CORS", func(ctx context.Context) []ConformanceTestResult {
			return NewCORSConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient)
		}},
	}

	for _, suite := range suites {
		fmt.Printf("Running %s tests...\n", suite.name)
		suiteStart := time.Now()

		suiteResults := suite.run(ctx)

		sSuiteResults := make([]ConformanceTestResult, len(suiteResults))
		copy(sSuiteResults, suiteResults)

		// Store results
		s.mu.Lock()
		s.SuiteResults[suite.name] = sSuiteResults
		s.AllResults = append(s.AllResults, sSuiteResults...)
		s.mu.Unlock()

		// Print suite summary
		suiteDuration := time.Since(suiteStart)
		passed := s.countPassed(sSuiteResults)
		failed := s.countFailed(sSuiteResults)
		total := len(sSuiteResults)

		fmt.Printf("  %s: %d/%d passed, %d failed (%v)\n",
			suite.name, passed, total, failed, suiteDuration.Round(time.Millisecond))
	}

	// Print overall summary
	elapsed := time.Since(startTime)
	passed := s.countPassed(s.AllResults)
	failed := s.countFailed(s.AllResults)
	total := len(s.AllResults)
	score := s.GetOverallConformanceScore()

	fmt.Printf("\n=== Conformance Test Summary ===\n")
	fmt.Printf("Total Tests: %d\n", total)
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)
	fmt.Printf("Conformance Score: %.2f%%\n", score)
	fmt.Printf("Total Time: %v\n", elapsed.Round(time.Millisecond))

	// Print category breakdown
	fmt.Printf("\n=== Category Breakdown ===\n")
	categories := s.GetResultsByCategory()
	for category, results := range categories {
		passed := s.countPassed(results)
		failed := s.countFailed(results)
		total := len(results)
		fmt.Printf("  %s: %d/%d passed, %d failed\n", category, passed, total, failed)
	}

	return nil
}

// RunSuite runs a specific conformance test suite by name
func (s *ConformanceSuite) RunSuite(ctx context.Context, suiteName string) ([]ConformanceTestResult, error) {
	switch strings.ToLower(suiteName) {
	case "contentnegotiation", "content_negotiation":
		return NewContentNegotiationConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient), nil
	case "conditionalrequest", "conditional_request":
		return NewConditionalRequestConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient), nil
	case "httpmethodmatrix", "http_method_matrix":
		return NewHTTPMethodMatrixConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient), nil
	case "rangecompression", "range_and_compression", "range_compression":
		return NewRangeCompressionConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient), nil
	case "storagedescription", "storage_description":
		return NewStorageDescriptionConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient), nil
	case "webidoidcdpop", "webid_oidc_dpop":
		return NewWebIDOIDCDPoPConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient), nil
	case "wacacp", "wac_acp":
		return NewWACACPConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient), nil
	case "cors":
		return NewCORSConformanceTests().Run(ctx, s.ServerURL, s.HTTPClient), nil
	default:
		return nil, fmt.Errorf("unknown suite: %s", suiteName)
	}
}

// GetOverallConformanceScore returns the overall conformance score across all suites
func (s *ConformanceSuite) GetOverallConformanceScore() float64 {
	if len(s.AllResults) == 0 {
		return 0.0
	}

	var passed int
	for _, result := range s.AllResults {
		if result.TestStatus == "passed" {
			passed++
		}
	}

	return float64(passed) / float64(len(s.AllResults)) * 100.0
}

// GetResultsByCategory returns results grouped by category
func (s *ConformanceSuite) GetResultsByCategory() map[string][]ConformanceTestResult {
	resultsByCategory := make(map[string][]ConformanceTestResult)

	for _, result := range s.AllResults {
		category := result.TestCategory
		resultsByCategory[category] = append(resultsByCategory[category], result)
	}

	return resultsByCategory
}

// GetResultsBySeverity returns results grouped by severity
func (s *ConformanceSuite) GetResultsBySeverity() map[string][]ConformanceTestResult {
	resultsBySeverity := make(map[string][]ConformanceTestResult)

	for _, result := range s.AllResults {
		severity := result.Severity
		if severity == "" {
			severity = "low"
		}
		resultsBySeverity[severity] = append(resultsBySeverity[severity], result)
	}

	return resultsBySeverity
}

// GetFailedTests returns all failed tests across all suites
func (s *ConformanceSuite) GetFailedTests() []ConformanceTestResult {
	var failed []ConformanceTestResult

	for _, result := range s.AllResults {
		if result.TestStatus == "failed" || result.TestStatus == "error" {
			failed = append(failed, result)
		}
	}

	return failed
}

// GetPassedTests returns all passed tests across all suites
func (s *ConformanceSuite) GetPassedTests() []ConformanceTestResult {
	var passed []ConformanceTestResult

	for _, result := range s.AllResults {
		if result.TestStatus == "passed" {
			passed = append(passed, result)
		}
	}

	return passed
}

// GenerateReport generates a conformance report in JSON format
func (s *ConformanceSuite) GenerateReport() (string, error) {
	report := map[string]interface{}{
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
		"server_url":         s.ServerURL,
		"total_tests":        len(s.AllResults),
		"passed_tests":       s.countPassed(s.AllResults),
		"failed_tests":       s.countFailed(s.AllResults),
		"conformance_score":  fmt.Sprintf("%.2f%%", s.GetOverallConformanceScore()),
		"suite_breakdown":    s.getSuiteBreakdown(),
		"category_breakdown": s.getCategoryBreakdown(),
		"severity_breakdown": s.getSeverityBreakdown(),
		"tests":              s.AllResults,
	}

	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// GenerateReportFile generates a conformance report and saves it to a file
func (s *ConformanceSuite) GenerateReportFile(filename string) error {
	report, err := s.GenerateReport()
	if err != nil {
		return err
	}

	return os.WriteFile(filename, []byte(report), 0644)
}

// PrintReport prints a formatted conformance report to stdout
func (s *ConformanceSuite) PrintReport() {
	fmt.Println("\n=== Solid Conformance Report ===")
	fmt.Println()

	// Overall summary
	fmt.Println("## Summary")
	fmt.Printf("- **Server URL**: %s\n", s.ServerURL)
	fmt.Printf("- **Total Tests**: %d\n", len(s.AllResults))
	fmt.Printf("- **Passed**: %d\n", s.countPassed(s.AllResults))
	fmt.Printf("- **Failed**: %d\n", s.countFailed(s.AllResults))
	fmt.Printf("- **Conformance Score**: %.2f%%\n", s.GetOverallConformanceScore())
	fmt.Println()

	// Suite breakdown
	fmt.Println("## Suite Breakdown")
	for suiteName, results := range s.SuiteResults {
		passed := s.countPassed(results)
		failed := s.countFailed(results)
		total := len(results)
		fmt.Printf("- **%s**: %d/%d passed, %d failed\n", suiteName, passed, total, failed)
	}
	fmt.Println()

	// Category breakdown
	fmt.Println("## Category Breakdown")
	categories := s.GetResultsByCategory()
	// Sort categories for consistent output
	var categoryNames []string
	for category := range categories {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)

	for _, category := range categoryNames {
		results := categories[category]
		passed := s.countPassed(results)
		failed := s.countFailed(results)
		total := len(results)
		fmt.Printf("- **%s**: %d/%d passed, %d failed\n", category, passed, total, failed)
	}
	fmt.Println()

	// Severity breakdown
	fmt.Println("## Severity Breakdown")
	severities := s.GetResultsBySeverity()
	// Sort severities for consistent output
	var severityNames []string
	for severity := range severities {
		severityNames = append(severityNames, severity)
	}
	sort.Strings(severityNames)

	for _, severity := range severityNames {
		results := severities[severity]
		passed := s.countPassed(results)
		failed := s.countFailed(results)
		total := len(results)
		fmt.Printf("- **%s**: %d/%d passed, %d failed\n", severity, passed, total, failed)
	}
	fmt.Println()

	// Failed tests
	failed := s.GetFailedTests()
	if len(failed) > 0 {
		fmt.Println("## Failed Tests")
		for _, result := range failed {
			fmt.Printf("### %s\n", result.TestName)
			fmt.Printf("- **Category**: %s\n", result.TestCategory)
			fmt.Printf("- **Status**: %s\n", result.TestStatus)
			fmt.Printf("- **Severity**: %s\n", result.Severity)
			if result.ErrorMessage != "" {
				fmt.Printf("- **Error**: %s\n", result.ErrorMessage)
			}
			if result.ErrorDetails != "" {
				fmt.Printf("- **Details**: %s\n", result.ErrorDetails)
			}
			if result.SolidSpecRef != "" {
				fmt.Printf("- **Spec Reference**: %s\n", result.SolidSpecRef)
			}
			fmt.Println()
		}
	}
}

// Helper methods

func (s *ConformanceSuite) countPassed(results []ConformanceTestResult) int {
	var count int
	for _, result := range results {
		if result.TestStatus == "passed" {
			count++
		}
	}
	return count
}

func (s *ConformanceSuite) countFailed(results []ConformanceTestResult) int {
	var count int
	for _, result := range results {
		if result.TestStatus == "failed" || result.TestStatus == "error" {
			count++
		}
	}
	return count
}

func (s *ConformanceSuite) getSuiteBreakdown() map[string]interface{} {
	breakdown := make(map[string]interface{})
	for suiteName, results := range s.SuiteResults {
		breakdown[suiteName] = map[string]interface{}{
			"total":  len(results),
			"passed": s.countPassed(results),
			"failed": s.countFailed(results),
			"score":  fmt.Sprintf("%.2f%%", float64(s.countPassed(results))/float64(len(results))*100),
		}
	}
	return breakdown
}

func (s *ConformanceSuite) getCategoryBreakdown() map[string]interface{} {
	categories := s.GetResultsByCategory()
	breakdown := make(map[string]interface{})
	for category, results := range categories {
		breakdown[category] = map[string]interface{}{
			"total":  len(results),
			"passed": s.countPassed(results),
			"failed": s.countFailed(results),
			"score":  fmt.Sprintf("%.2f%%", float64(s.countPassed(results))/float64(len(results))*100),
		}
	}
	return breakdown
}

func (s *ConformanceSuite) getSeverityBreakdown() map[string]interface{} {
	severities := s.GetResultsBySeverity()
	breakdown := make(map[string]interface{})
	for severity, results := range severities {
		breakdown[severity] = map[string]interface{}{
			"total":  len(results),
			"passed": s.countPassed(results),
			"failed": s.countFailed(results),
			"score":  fmt.Sprintf("%.2f%%", float64(s.countPassed(results))/float64(len(results))*100),
		}
	}
	return breakdown
}

// ConformanceTestRunner is the interface that all conformance test suites must implement
type ConformanceTestRunner interface {
	Run(ctx context.Context, serverURL string, client *http.Client) []ConformanceTestResult
	GetConformanceScore() float64
}

// RegisterSuite registers a custom conformance test suite
func (s *ConformanceSuite) RegisterSuite(name string, suite ConformanceTestRunner) {
	// This would be used to add custom test suites dynamically
	// For now, we just add it to the suite results
	// In a full implementation, we'd run the suite and store results
	_ = name
	_ = suite
}
