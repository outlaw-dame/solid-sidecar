// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file defines common types used across all conformance test suites.
package conformance

import (
	"time"
)

// ConformanceTestResult represents the result of a conformance test.
// This is the common result type used by all conformance test suites.
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

// TestConfig holds common configuration for conformance tests
type TestConfig struct {
	Timeout     time.Duration
	StrictMode  bool
	DebugOutput bool
	ServerURL   string
}

// NewTestConfig creates a new test configuration with sensible defaults
func NewTestConfig() *TestConfig {
	return &TestConfig{
		Timeout:    30 * time.Second,
		StrictMode: true,
	}
}

// Severity constants for test categorization
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// TestStatus constants
const (
	TestStatusPassed  = "passed"
	TestStatusFailed  = "failed"
	TestStatusSkipped = "skipped"
	TestStatusError   = "error"
)

// TargetType constants for HTTP method matrix tests
const (
	TargetTypeResource    = "resource"
	TargetTypeContainer   = "container"
	TargetTypePolicy      = "policy"
	TargetTypeDescription = "description"
	TargetTypeAuxiliary   = "auxiliary"
)

// Method constants
const (
	MethodGET     = "GET"
	MethodHEAD    = "HEAD"
	MethodPUT     = "PUT"
	MethodPOST    = "POST"
	MethodDELETE  = "DELETE"
	MethodPATCH   = "PATCH"
	MethodOPTIONS = "OPTIONS"
)
