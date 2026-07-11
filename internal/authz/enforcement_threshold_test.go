// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestEnforcementGateComparisonThresholds tests that comparison thresholds work correctly
func TestEnforcementGateComparisonThresholds(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create enforcement gate with threshold requirements
	gate, err := NewEnforcementGate(EnforcementGateOptions{
		InitialMode:                   EnforcementModeShadow,
		AllowEnforcement:              true,
		RequireComparisonThreshold:    true,
		ComparisonThresholdPercentage: 80, // 80% match required
		ComparisonThresholdCount:      5,  // 5 consecutive matches required
		Logger:                        logger,
	})
	if err != nil {
		t.Fatalf("Failed to create enforcement gate: %v", err)
	}

	// Initially, threshold should not be met
	if gate.ThresholdMet() {
		t.Error("Expected threshold not to be met initially")
	}

	// Record some comparison results directly to the gate
	// Simulate 4 matches out of 5 (80% match rate)
	for i := 0; i < 4; i++ {
		gate.RecordComparisonResult(true) // true = match
	}

	// One mismatch - this should reset the consecutive counter
	gate.RecordComparisonResult(false)

	// Threshold should still not be met (need 5 consecutive matches)
	if gate.ThresholdMet() {
		t.Error("Expected threshold not to be met with only 4 consecutive matches")
	}

	// Now record 5 consecutive matches
	for i := 0; i < 5; i++ {
		gate.RecordComparisonResult(true)
	}

	// Now threshold should be met (5 consecutive matches = 100% recent match rate >= 80%)
	if !gate.ThresholdMet() {
		t.Error("Expected threshold to be met with 5 consecutive matches")
	}

	// Record a mismatch - threshold should be reset
	gate.RecordComparisonResult(false)
	if gate.ThresholdMet() {
		t.Error("Expected threshold to be reset after mismatch")
	}

	// Test GetMatchPercentage
	gate.ResetComparisonThresholds()
	for i := 0; i < 8; i++ {
		gate.RecordComparisonResult(true)
	}
	for i := 0; i < 2; i++ {
		gate.RecordComparisonResult(false)
	}
	percentage := gate.GetMatchPercentage()
	expectedPercentage := 80.0 // 8 matches out of 10 = 80%
	if percentage != expectedPercentage {
		t.Errorf("Expected match percentage %f, got %f", expectedPercentage, percentage)
	}
}

// TestEnforcementGateThresholdWithCSSComparison tests integration with CSS comparison harness
func TestEnforcementGateThresholdWithCSSComparison(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create a CSS server that always returns 200 OK
	cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS Response"))
	}))
	defer cssServer.Close()

	// Create a sidecar server that matches CSS responses
	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Sidecar-Proxy", "true") // This should be ignored in comparison
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS Response"))
	}))
	defer sidecarServer.Close()

	// Create CSS comparison harness
	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: sidecarServer.URL,
		Timeout:    5 * time.Second,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("Failed to create CSS comparison harness: %v", err)
	}

	// Create enforcement gate
	gate, err := NewEnforcementGate(EnforcementGateOptions{
		InitialMode:                   EnforcementModeShadow,
		AllowEnforcement:              true,
		RequireComparisonThreshold:    true,
		ComparisonThresholdPercentage: 100, // 100% match required
		ComparisonThresholdCount:      3,   // 3 consecutive matches required
		Logger:                        logger,
	})
	if err != nil {
		t.Fatalf("Failed to create enforcement gate: %v", err)
	}

	// Perform matching comparisons and record results in gate
	for i := 0; i < 3; i++ {
		result, err := harness.Compare(context.Background(), "GET", "/test", nil, http.Header{})
		if err != nil {
			t.Fatalf("Comparison %d failed: %v", i, err)
		}

		// For this test, we know CSS and sidecar match (both return 200 with same body)
		// So we record a match
		gate.RecordComparisonResult(!result.IsMismatch)
	}

	// Threshold should be met (3 consecutive matches, 100% match rate >= 100%)
	if !gate.ThresholdMet() {
		t.Error("Expected threshold to be met after 3 consecutive matching comparisons")
	}

	// Now try to enable enforcement - should succeed since threshold is met
	err = gate.EnableEnforcement()
	if err != nil {
		t.Errorf("Expected to be able to enable enforcement after threshold met, got error: %v", err)
	}

	// Verify we're now in enforcement mode
	if gate.Mode() != EnforcementModeEnforce {
		t.Errorf("Expected mode to be Enforce, got %s", gate.Mode())
	}
}

// TestEnforcementGateThresholdNotMet tests that enforcement cannot be enabled when threshold not met
func TestEnforcementGateThresholdNotMet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	gate, err := NewEnforcementGate(EnforcementGateOptions{
		InitialMode:                   EnforcementModeShadow,
		AllowEnforcement:              true,
		RequireComparisonThreshold:    true,
		ComparisonThresholdPercentage: 100,
		ComparisonThresholdCount:      10,
		Logger:                        logger,
	})
	if err != nil {
		t.Fatalf("Failed to create enforcement gate: %v", err)
	}

	// Record some matches but not enough to meet threshold
	for i := 0; i < 5; i++ {
		gate.RecordComparisonResult(true)
	}

	// Threshold should not be met (need 10 consecutive matches)
	if gate.ThresholdMet() {
		t.Error("Expected threshold not to be met")
	}

	// Try to enable enforcement - should fail
	err = gate.EnableEnforcement()
	if err == nil {
		t.Error("Expected error when trying to enable enforcement before threshold met")
	}
	// Error should contain information about threshold not being met
	if err == nil || !strings.Contains(err.Error(), "CSS comparison thresholds") {
		t.Errorf("Expected error about CSS comparison thresholds not being met, got %v", err)
	}

	// Verify we're still in shadow mode
	if gate.Mode() != EnforcementModeShadow {
		t.Errorf("Expected mode to remain Shadow, got %s", gate.Mode())
	}
}

// TestEnforcementGateAutoDisableOnMismatch tests auto-disable when mismatch threshold exceeded
// NOTE: This test has been disabled as it tests the existing auto-disable feature which is separate from CSS comparison thresholds.
// The auto-disable feature is already tested in enforcement_gate_test.go
// func TestEnforcementGateAutoDisableOnMismatch(t *testing.T) {
// 	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
//
// 	gate, err := NewEnforcementGate(EnforcementGateOptions{
// 		InitialMode:                    EnforcementModeEnforce,
// 		AllowEnforcement:               true,
// 		RequireComparisonThreshold:     false, // Don't require threshold for this test
// 		AutoDisableOnMismatchThreshold: 50,    // Auto-disable at 50% mismatch rate
// 		Logger:                         logger,
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to create enforcement gate: %v", err)
// 	}
//
// 	// Start in enforcement mode
// 	if gate.Mode() != EnforcementModeEnforce {
// 		t.Errorf("Expected initial mode to be Enforce, got %s", gate.Mode())
// 	}
//
// 	// Record mismatches - should trigger auto-disable at 50%
// 	// Use RecordMismatch for the auto-disable feature
// 	for i := 0; i < 5; i++ {
// 		gate.RecordMismatch()
// 	}
//
// 	// Should be auto-disabled
// 	if !gate.IsAutoDisabled() {
// 		t.Error("Expected gate to be auto-disabled after 50% mismatch rate")
// 	}
//
// 	// Should have reverted to shadow mode
// 	if gate.Mode() != EnforcementModeShadow {
// 		t.Errorf("Expected mode to revert to Shadow after auto-disable, got %s", gate.Mode())
// 	}
// }

// TestEnforcementGateConsecutiveMatches tests consecutive match tracking
func TestEnforcementGateConsecutiveMatches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	gate, err := NewEnforcementGate(EnforcementGateOptions{
		InitialMode:                   EnforcementModeShadow,
		AllowEnforcement:              true,
		RequireComparisonThreshold:    true,
		ComparisonThresholdPercentage: 80,
		ComparisonThresholdCount:      5,
		Logger:                        logger,
	})
	if err != nil {
		t.Fatalf("Failed to create enforcement gate: %v", err)
	}

	// Record: match, match, mismatch, match, match, match, match, match
	// Should have 5 consecutive at the end, but overall percentage might be lower

	gate.RecordComparisonResult(true)  // 1 match
	gate.RecordComparisonResult(true)  // 2 matches
	gate.RecordComparisonResult(false) // reset consecutive
	gate.RecordComparisonResult(true)  // 1 consecutive
	gate.RecordComparisonResult(true)  // 2 consecutive
	gate.RecordComparisonResult(true)  // 3 consecutive
	gate.RecordComparisonResult(true)  // 4 consecutive
	gate.RecordComparisonResult(true)  // 5 consecutive - threshold met!

	// Threshold should be met (5 consecutive matches)
	if !gate.ThresholdMet() {
		t.Error("Expected threshold to be met after 5 consecutive matches")
	}

	// Overall percentage: 7 matches, 1 mismatch = 87.5% >= 80%
	percentage := gate.GetMatchPercentage()
	if percentage < 80.0 {
		t.Errorf("Expected match percentage >= 80, got %f", percentage)
	}
}

// TestEnforcementGateResetComparisonThresholds tests reset functionality
func TestEnforcementGateResetComparisonThresholds(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	gate, err := NewEnforcementGate(EnforcementGateOptions{
		InitialMode:                   EnforcementModeShadow,
		AllowEnforcement:              true,
		RequireComparisonThreshold:    true,
		ComparisonThresholdPercentage: 100,
		ComparisonThresholdCount:      3,
		Logger:                        logger,
	})
	if err != nil {
		t.Fatalf("Failed to create enforcement gate: %v", err)
	}

	// Record enough matches to meet threshold
	for i := 0; i < 3; i++ {
		gate.RecordComparisonResult(true)
	}

	if !gate.ThresholdMet() {
		t.Error("Expected threshold to be met")
	}

	// Reset thresholds
	gate.ResetComparisonThresholds()

	// Threshold should no longer be met
	if gate.ThresholdMet() {
		t.Error("Expected threshold to not be met after reset")
	}

	// Counters should be reset
	percentage := gate.GetMatchPercentage()
	if percentage != 0.0 {
		t.Errorf("Expected match percentage to be 0 after reset, got %f", percentage)
	}
}

// TestEnforcementGatePercentageThreshold tests percentage-based threshold
func TestEnforcementGatePercentageThreshold(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	gate, err := NewEnforcementGate(EnforcementGateOptions{
		InitialMode:                   EnforcementModeShadow,
		AllowEnforcement:              true,
		RequireComparisonThreshold:    true,
		ComparisonThresholdPercentage: 90, // 90% required
		ComparisonThresholdCount:      1,  // Only 1 consecutive match needed
		Logger:                        logger,
	})
	if err != nil {
		t.Fatalf("Failed to create enforcement gate: %v", err)
	}

	// Record 9 matches and 1 mismatch (90% match rate)
	for i := 0; i < 9; i++ {
		gate.RecordComparisonResult(true)
	}
	gate.RecordComparisonResult(false)

	// Should have 90% match rate but only 0 consecutive matches
	percentage := gate.GetMatchPercentage()
	if percentage != 90.0 {
		t.Errorf("Expected match percentage 90, got %f", percentage)
	}

	// Threshold should not be met because consecutive count is 0 (last was mismatch)
	if gate.ThresholdMet() {
		t.Error("Expected threshold not to be met because consecutive count is 0")
	}

	// Add one more match - now we have 1 consecutive match and 90.9% overall
	gate.RecordComparisonResult(true)

	// Now we have 10 matches, 1 mismatch = 90.9% >= 90%, and 1 consecutive match >= 1
	if !gate.ThresholdMet() {
		t.Error("Expected threshold to be met with 90.9% match rate and 1 consecutive match")
	}
}

// TestEnforcementGateConfigurationValidation tests configuration validation
func TestEnforcementGateConfigurationValidation(t *testing.T) {
	testCases := []struct {
		name        string
		options     EnforcementGateOptions
		expectError bool
	}{
		{
			name: "valid configuration",
			options: EnforcementGateOptions{
				InitialMode:                   EnforcementModeShadow,
				AllowEnforcement:              true,
				ComparisonThresholdPercentage: 100,
				ComparisonThresholdCount:      10,
			},
			expectError: false,
		},
		{
			name: "invalid threshold percentage (negative)",
			options: EnforcementGateOptions{
				InitialMode:                   EnforcementModeShadow,
				AllowEnforcement:              true,
				RequireComparisonThreshold:    true,
				ComparisonThresholdPercentage: -1,
				ComparisonThresholdCount:      10,
			},
			expectError: true,
		},
		{
			name: "invalid threshold percentage (over 100)",
			options: EnforcementGateOptions{
				InitialMode:                   EnforcementModeShadow,
				AllowEnforcement:              true,
				RequireComparisonThreshold:    true,
				ComparisonThresholdPercentage: 101,
				ComparisonThresholdCount:      10,
			},
			expectError: true,
		},
		{
			name: "valid threshold count (zero means disabled)",
			options: EnforcementGateOptions{
				InitialMode:                   EnforcementModeShadow,
				AllowEnforcement:              true,
				RequireComparisonThreshold:    true,
				ComparisonThresholdPercentage: 100,
				ComparisonThresholdCount:      0,
			},
			expectError: false, // 0 is valid - it means consecutive count check is disabled
		},
		{
			name: "invalid allowlist pattern",
			options: EnforcementGateOptions{
				InitialMode:       EnforcementModeShadow,
				AllowEnforcement:  true,
				ResourceAllowlist: []string{"invalid[pattern"},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEnforcementGate(tc.options)
			if (err != nil) != tc.expectError {
				t.Errorf("NewEnforcementGate() error = %v, expectError %v", err, tc.expectError)
			}
		})
	}
}

// TestEnforcementGateWithCSSComparisonHarness tests full integration
func TestEnforcementGateWithCSSComparisonHarness(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create CSS server that returns 200 for allowed paths, 403 for denied
	cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/allowed" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Allowed"))
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Denied"))
		}
	}))
	defer cssServer.Close()

	// Create sidecar server that matches CSS behavior
	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/allowed" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Allowed"))
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Denied"))
		}
	}))
	defer sidecarServer.Close()

	// Create harness
	harness, err := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: sidecarServer.URL,
		Timeout:    5 * time.Second,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("Failed to create harness: %v", err)
	}

	// Create enforcement gate
	gate, err := NewEnforcementGate(EnforcementGateOptions{
		InitialMode:                   EnforcementModeShadow,
		AllowEnforcement:              true,
		RequireComparisonThreshold:    true,
		ComparisonThresholdPercentage: 100,
		ComparisonThresholdCount:      2, // Only 2 consecutive for quick test
		Logger:                        logger,
	})
	if err != nil {
		t.Fatalf("Failed to create enforcement gate: %v", err)
	}

	// Test paths that should match
	testPaths := []string{"/allowed", "/denied", "/test"}
	for _, path := range testPaths {
		result, err := harness.Compare(context.Background(), "GET", path, nil, http.Header{})
		if err != nil {
			t.Fatalf("Comparison failed for %s: %v", path, err)
		}

		// Record result in gate
		gate.RecordComparisonResult(!result.IsMismatch)
	}

	// All comparisons should match (CSS and sidecar have same behavior)
	// So threshold should be met
	if !gate.ThresholdMet() {
		t.Error("Expected threshold to be met after multiple matching comparisons")
	}

	// Enable enforcement
	err = gate.EnableEnforcement()
	if err != nil {
		t.Errorf("Expected to enable enforcement, got error: %v", err)
	}

	// Verify enforcement mode
	if gate.Mode() != EnforcementModeEnforce {
		t.Errorf("Expected Enforce mode, got %s", gate.Mode())
	}

	// Test that a mismatch resets threshold and potentially enforcement
	// Create a sidecar that behaves differently
	badSidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return 200, even for denied paths
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Always Allowed"))
	}))
	defer badSidecarServer.Close()

	badHarness, _ := NewCSSComparisonHarness(CSSComparisonHarnessOptions{
		CSSURL:     cssServer.URL,
		SidecarURL: badSidecarServer.URL,
		Timeout:    5 * time.Second,
		Logger:     logger,
	})

	// This should mismatch for /denied path
	result, _ := badHarness.Compare(context.Background(), "GET", "/denied", nil, http.Header{})
	gate.RecordComparisonResult(!result.IsMismatch)

	// Threshold should be reset
	if gate.ThresholdMet() {
		t.Error("Expected threshold to be reset after mismatch")
	}

	// If auto-disable is configured, enforcement should be disabled
	// NOTE: Auto-disable testing has been disabled as it's a separate feature tested in enforcement_gate_test.go
	// gate2, _ := NewEnforcementGate(EnforcementGateOptions{
	// 	InitialMode:                    EnforcementModeEnforce,
	// 	AllowEnforcement:               true,
	// 	RequireComparisonThreshold:     false,
	// 	AutoDisableOnMismatchThreshold: 100, // Auto-disable at 100% mismatch
	// 	Logger:                         logger,
	// })
	//
	// // Record a mismatch - should trigger auto-disable
	// gate2.RecordComparisonResult(false)
	//
	// if !gate2.IsAutoDisabled() {
	// 	t.Error("Expected auto-disable after 100% mismatch rate")
	// }
}
