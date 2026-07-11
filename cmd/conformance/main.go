// Package main provides the command-line interface for Solid conformance testing
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/conformance"
)

const (
	version = "0.1.0"
	name    = "solid-conformance"
)

// Config holds the command-line configuration
type Config struct {
	ServerURL  string
	Output     string
	Format     string
	Suite      string
	ListSuites bool
	Timeout    time.Duration
	StrictMode bool
	Debug      bool
	Version    bool
	Help       bool
}

func main() {
	cfg := parseFlags()

	if cfg.Version {
		printVersion()
		os.Exit(0)
	}

	if cfg.Help || cfg.ServerURL == "" {
		printUsage()
		os.Exit(0)
	}

	if cfg.ListSuites {
		listSuites()
		os.Exit(0)
	}

	// Handle interrupt signal
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()
	defer cancel()

	// Run conformance tests
	if err := runConformanceTests(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// parseFlags parses command-line flags
func parseFlags() Config {
	cfg := Config{
		Timeout:    30 * time.Second,
		StrictMode: true,
	}

	flag.StringVar(&cfg.ServerURL, "server", "", "Solid server URL to test (required)")
	flag.StringVar(&cfg.Output, "output", "", "Output file for report")
	flag.StringVar(&cfg.Format, "format", "json", "Output format: json, markdown, text")
	flag.StringVar(&cfg.Suite, "suite", "all", "Test suite to run: all, content_negotiation, conditional_request, http_method_matrix, range_compression, storage_description, webid_oidc_dpop, wac_acp, cors")
	flag.BoolVar(&cfg.ListSuites, "list-suites", false, "List available test suites")
	flag.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "Request timeout")
	flag.BoolVar(&cfg.StrictMode, "strict", true, "Strict mode (fail on warnings)")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug output")
	flag.BoolVar(&cfg.Version, "version", false, "Print version")
	flag.BoolVar(&cfg.Help, "help", false, "Print help")

	flag.Parse()

	return cfg
}

// printVersion prints the version information
func printVersion() {
	fmt.Printf("%s version %s\n", name, version)
	fmt.Printf("Solid Protocol Conformance Test Suite\n")
	fmt.Printf("Repository: github.com/outlaw-dame/solid-sidecar\n")
}

// printUsage prints the usage information
func printUsage() {
	printVersion()
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Printf("  %s [options]\n\n", name)
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s --server http://localhost:8080\n", name)
	fmt.Printf("  %s --server http://localhost:8080 --suite conditional_request --format text\n", name)
	fmt.Printf("  %s --server http://localhost:8080 --output conformance-report.json\n", name)
	fmt.Printf("  %s --list-suites\n", name)
}

// listSuites lists all available test suites
func listSuites() {
	suites := []string{
		"all",
		"content_negotiation",
		"conditional_request",
		"http_method_matrix",
		"range_compression",
		"storage_description",
		"webid_oidc_dpop",
		"wac_acp",
		"cors",
	}

	fmt.Println("Available Test Suites:")
	for _, suite := range suites {
		fmt.Printf("  - %s\n", suite)
	}
}

// runConformanceTests runs the conformance tests based on configuration
func runConformanceTests(ctx context.Context, cfg Config) error {
	// Create HTTP client
	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	// Create conformance suite
	suite := conformance.NewConformanceSuite(cfg.ServerURL)
	suite.HTTPClient = client
	suite.Timeout = cfg.Timeout
	suite.StrictMode = cfg.StrictMode
	suite.DebugOutput = cfg.Debug

	// Run tests
	startTime := time.Now()

	if cfg.Suite == "all" {
		// Run all test suites
		if err := suite.RunAll(ctx); err != nil {
			return fmt.Errorf("failed to run conformance tests: %w", err)
		}
	} else {
		// Run specific suite
		results, err := suite.RunSuite(ctx, cfg.Suite)
		if err != nil {
			return fmt.Errorf("failed to run suite '%s': %w", cfg.Suite, err)
		}
		// Store results for output
		suite.AllResults = results
	}

	elapsed := time.Since(startTime)

	// Generate report
	if cfg.Output != "" {
		if err := suite.GenerateReportFile(cfg.Output); err != nil {
			return fmt.Errorf("failed to generate report file: %w", err)
		}
		fmt.Printf("Report saved to: %s\n", cfg.Output)
	}

	// Print report based on format
	switch strings.ToLower(cfg.Format) {
	case "json":
		printJSONReport(suite)
	case "markdown":
		printMarkdownReport(suite, elapsed)
	default:
		suite.PrintReport()
	}

	fmt.Printf("\nConformance testing completed in %v\n", elapsed.Round(time.Millisecond))

	return nil
}

// printJSONReport prints the report in JSON format
func printJSONReport(suite *conformance.ConformanceSuite) {
	report, err := suite.GenerateReport()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating report: %v\n", err)
		return
	}
	fmt.Println(report)
}

// countPassed counts passed tests in a result slice
func countPassed(results []conformance.ConformanceTestResult) int {
	var count int
	for _, result := range results {
		if result.TestStatus == conformance.TestStatusPassed {
			count++
		}
	}
	return count
}

// countFailed counts failed tests in a result slice
func countFailed(results []conformance.ConformanceTestResult) int {
	var count int
	for _, result := range results {
		if result.TestStatus == conformance.TestStatusFailed || result.TestStatus == conformance.TestStatusError {
			count++
		}
	}
	return count
}

// printMarkdownReport prints the report in Markdown format
func printMarkdownReport(suite *conformance.ConformanceSuite, elapsed time.Duration) {
	var sb strings.Builder

	// Header
	sb.WriteString("# Solid Conformance Report\n\n")

	// Metadata
	sb.WriteString("## Test Metadata\n\n")
	sb.WriteString(fmt.Sprintf("- **Server URL**: %s\n", suite.ServerURL))
	sb.WriteString(fmt.Sprintf("- **Test Date**: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Total Duration**: %v\n", elapsed.Round(time.Millisecond)))
	sb.WriteString("\n")

	// Summary
	sb.WriteString("## Test Summary\n\n")
	passed := suite.GetPassedTests()
	failed := suite.GetFailedTests()
	total := len(suite.AllResults)
	score := suite.GetOverallConformanceScore()

	sb.WriteString(fmt.Sprintf("- **Total Tests**: %d\n", total))
	sb.WriteString(fmt.Sprintf("- **Passed**: %d\n", len(passed)))
	sb.WriteString(fmt.Sprintf("- **Failed**: %d\n", len(failed)))
	sb.WriteString(fmt.Sprintf("- **Conformance Score**: %.2f%%\n", score))
	sb.WriteString("\n")

	// Suite Breakdown
	sb.WriteString("## Suite Breakdown\n\n")
	sb.WriteString("| Suite | Total | Passed | Failed | Score |\n")
	sb.WriteString("|-------|-------|--------|--------|-------|\n")
	for suiteName, results := range suite.SuiteResults {
		passed := countPassed(results)
		failed := countFailed(results)
		total := len(results)
		score := float64(passed) / float64(total) * 100.0
		if total == 0 {
			score = 0
		}
		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %.1f%% |\n", suiteName, total, passed, failed, score))
	}
	sb.WriteString("\n")

	// Category Breakdown
	sb.WriteString("## Category Breakdown\n\n")
	categories := suite.GetResultsByCategory()
	// Sort categories
	var categoryNames []string
	for category := range categories {
		categoryNames = append(categoryNames, category)
	}
	// Simple bubble sort for consistent output
	for i := 0; i < len(categoryNames)-1; i++ {
		for j := 0; j < len(categoryNames)-i-1; j++ {
			if categoryNames[j] > categoryNames[j+1] {
				categoryNames[j], categoryNames[j+1] = categoryNames[j+1], categoryNames[j]
			}
		}
	}

	sb.WriteString("| Category | Total | Passed | Failed | Score |\n")
	sb.WriteString("|----------|-------|--------|--------|-------|\n")
	for _, category := range categoryNames {
		results := categories[category]
		passed := countPassed(results)
		failed := countFailed(results)
		total := len(results)
		score := float64(passed) / float64(total) * 100.0
		if total == 0 {
			score = 0
		}
		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %.1f%% |\n", category, total, passed, failed, score))
	}
	sb.WriteString("\n")

	// Failed Tests
	if len(failed) > 0 {
		sb.WriteString("## Failed Tests\n\n")
		for _, result := range failed {
			sb.WriteString(fmt.Sprintf("### %s (%s)\n\n", result.TestName, result.TestID))
			sb.WriteString(fmt.Sprintf("- **Category**: %s\n", result.TestCategory))
			sb.WriteString(fmt.Sprintf("- **Status**: %s\n", result.TestStatus))
			sb.WriteString(fmt.Sprintf("- **Severity**: %s\n", result.Severity))
			if result.ErrorMessage != "" {
				sb.WriteString(fmt.Sprintf("- **Error**: %s\n", result.ErrorMessage))
			}
			if result.ErrorDetails != "" {
				sb.WriteString(fmt.Sprintf("- **Details**: %s\n", result.ErrorDetails))
			}
			if result.SolidSpecRef != "" {
				sb.WriteString(fmt.Sprintf("- **Spec Reference**: %s\n", result.SolidSpecRef))
			}
			sb.WriteString("\n")
		}
	}

	fmt.Println(sb.String())
}
