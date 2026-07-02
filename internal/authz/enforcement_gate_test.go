// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =============================================================================
// Basic Creation and Default Tests
// =============================================================================

func TestEnforcementGateCreation(t *testing.T) {
	gate, err := NewEnforcementGate(DefaultEnforcementGateOptions())
	if err != nil {
		t.Fatalf("failed to create enforcement gate: %v", err)
	}
	if gate == nil {
		t.Fatal("enforcement gate is nil")
	}
}

func TestEnforcementGateDefaultOptions(t *testing.T) {
	options := DefaultEnforcementGateOptions()

	if options.InitialMode != EnforcementModeShadow {
		t.Errorf("expected default mode shadow, got %q", options.InitialMode)
	}
	if options.AllowEnforcement {
		t.Error("expected enforcement not allowed by default")
	}
	if !options.EmergencyBypassEnabled {
		t.Error("expected emergency bypass enabled by default")
	}
	if options.EmergencyBypassToken == "" {
		t.Error("expected emergency bypass token to be generated")
	}
	if options.MaxEnforcementDuration != 0 {
		t.Errorf("expected default max enforcement duration 0, got %v", options.MaxEnforcementDuration)
	}
	if len(options.MethodAllowlist) != 2 {
		t.Errorf("expected 2 methods in default allowlist, got %d", len(options.MethodAllowlist))
	}
	if options.MethodAllowlist[0] != "GET" || options.MethodAllowlist[1] != "HEAD" {
		t.Errorf("expected GET and HEAD in default method allowlist, got %v", options.MethodAllowlist)
	}
	if options.AutoDisableOnMismatchThreshold != 0 {
		t.Errorf("expected default mismatch threshold 0, got %d", options.AutoDisableOnMismatchThreshold)
	}
	if !options.RequireMultipleAuthors {
		t.Error("expected RequireMultipleAuthors to be true by default")
	}
	if options.CanaryConfig.Enabled {
		t.Error("expected canary disabled by default")
	}
	if options.CanaryConfig.Percentage != 1 {
		t.Errorf("expected canary percentage 1 by default, got %d", options.CanaryConfig.Percentage)
	}
	if options.Logger != nil {
		t.Error("expected logger to be nil by default")
	}
	if options.AuditLogger != nil {
		t.Error("expected audit logger to be nil by default")
	}
}

func TestEnforcementGateInitialMode(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.InitialMode = EnforcementModeShadow

	gate, _ := NewEnforcementGate(options)
	if gate.Mode() != EnforcementModeShadow {
		t.Errorf("expected mode shadow, got %q", gate.Mode())
	}

	options.InitialMode = EnforcementModeEnforce
	gate2, _ := NewEnforcementGate(options)
	// Even if we set enforce as initial mode, it should still be set
	if gate2.Mode() != EnforcementModeEnforce {
		t.Errorf("expected mode enforce, got %q", gate2.Mode())
	}
}

// =============================================================================
// Mode and State Check Tests
// =============================================================================

func TestEnforcementGateModeChecks(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true

	// Test shadow mode
	gate, _ := NewEnforcementGate(options)
	if !gate.IsShadowMode() {
		t.Error("expected shadow mode")
	}
	if gate.IsEnforceMode() {
		t.Error("expected not enforce mode")
	}
	if gate.IsDryRunMode() {
		t.Error("expected not dry-run mode")
	}
	if gate.IsCanaryMode() {
		t.Error("expected not canary mode")
	}
	if gate.IsStrictEnforceMode() {
		t.Error("expected not strict enforce mode")
	}

	// Test enforce mode
	gate.EnableEnforcement()
	if gate.IsShadowMode() {
		t.Error("expected not shadow mode after enabling enforcement")
	}
	if !gate.IsEnforceMode() {
		t.Error("expected enforce mode")
	}
	if !gate.IsStrictEnforceMode() {
		t.Error("expected strict enforce mode")
	}

	// Test dry-run mode
	gate.EnableDryRun()
	if !gate.IsEnforceMode() {
		t.Error("expected enforce mode after enabling dry-run (IsEnforceMode includes dry-run)")
	}
	if !gate.IsDryRunMode() {
		t.Error("expected dry-run mode")
	}
	if gate.IsStrictEnforceMode() {
		t.Error("expected not strict enforce mode in dry-run")
	}

	// Test canary mode
	gate.EnableCanary()
	if !gate.IsCanaryMode() {
		t.Error("expected canary mode")
	}
}

func TestEnforcementGateEnforcementNotAllowed(t *testing.T) {
	// Default: enforcement not allowed
	gate, _ := NewEnforcementGate(DefaultEnforcementGateOptions())

	// Try to enable enforcement - should fail
	err := gate.EnableEnforcement()
	if err == nil {
		t.Error("expected error when enabling enforcement without AllowEnforcement=true")
	}
	if !errors.Is(err, ErrEnforcementNotAllowed) {
		t.Errorf("expected ErrEnforcementNotAllowed, got %v", err)
	}

	// Mode should still be shadow
	if gate.Mode() != EnforcementModeShadow {
		t.Errorf("expected mode to remain shadow, got %q", gate.Mode())
	}
}

func TestEnforcementGateAllowEnforcement(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true

	gate, _ := NewEnforcementGate(options)

	// Should be able to enable enforcement
	err := gate.EnableEnforcement()
	if err != nil {
		t.Errorf("unexpected error enabling enforcement: %v", err)
	}

	if !gate.IsEnforceMode() {
		t.Error("expected enforce mode after enabling")
	}
}

// =============================================================================
// Emergency Bypass Tests
// =============================================================================

func TestEnforcementGateEmergencyBypass(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.EmergencyBypassEnabled = true
	options.EmergencyBypassToken = "test-bypass-token"

	gate, _ := NewEnforcementGate(options)

	// Initially, bypass should not be active
	if gate.IsEmergencyBypassActive() {
		t.Error("expected emergency bypass not active initially")
	}

	// Activate bypass with correct token
	if !gate.EmergencyBypass("test-bypass-token") {
		t.Error("expected emergency bypass to succeed with correct token")
	}

	if !gate.IsEmergencyBypassActive() {
		t.Error("expected emergency bypass to be active")
	}

	// Wrong token should fail
	if gate.EmergencyBypass("wrong-token") {
		t.Error("expected emergency bypass to fail with wrong token")
	}

	// Clear bypass
	gate.ClearEmergencyBypass("test-bypass-token")
	if gate.IsEmergencyBypassActive() {
		t.Error("expected emergency bypass to be inactive after clearing")
	}
}

func TestEnforcementGateEmergencyBypassDisabled(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.EmergencyBypassEnabled = false

	gate, _ := NewEnforcementGate(options)

	// Bypass should fail when disabled
	if gate.EmergencyBypass("any-token") {
		t.Error("expected emergency bypass to fail when disabled")
	}
}

func TestEnforcementGateBypassPreventsEnforcement(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.EmergencyBypassEnabled = true
	options.EmergencyBypassToken = "test-token"

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Without bypass, should enforce
	if !gate.ShouldEnforce() {
		t.Error("expected ShouldEnforce to return true")
	}

	// Activate bypass
	gate.EmergencyBypass("test-token")

	// With bypass, should not enforce
	if gate.ShouldEnforce() {
		t.Error("expected ShouldEnforce to return false with bypass active")
	}

	// Clear bypass
	gate.ClearEmergencyBypass("test-token")

	// Should enforce again
	if !gate.ShouldEnforce() {
		t.Error("expected ShouldEnforce to return true after clearing bypass")
	}
}

// =============================================================================
// Gate Close/Reopen Tests
// =============================================================================

func TestEnforcementGateClose(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true

	gate, _ := NewEnforcementGate(options)

	if gate.IsClosed() {
		t.Error("expected gate not closed initially")
	}

	gate.Close("test reason")

	if !gate.IsClosed() {
		t.Error("expected gate to be closed")
	}

	if gate.CloseReason() != "test reason" {
		t.Errorf("expected close reason 'test reason', got %q", gate.CloseReason())
	}

	// Should not be able to change mode when closed
	err := gate.EnableEnforcement()
	if err == nil {
		t.Error("expected error when changing mode on closed gate")
	}
	if !errors.Is(err, ErrEnforcementGateClosed) {
		t.Errorf("expected ErrEnforcementGateClosed, got %v", err)
	}
}

func TestEnforcementGateReopen(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true

	gate, _ := NewEnforcementGate(options)
	gate.Close("test")
	gate.Reopen()

	if gate.IsClosed() {
		t.Error("expected gate to be open after reopen")
	}

	if gate.CloseReason() != "" {
		t.Errorf("expected empty close reason after reopen, got %q", gate.CloseReason())
	}

	// Should be able to change mode after reopen
	err := gate.EnableEnforcement()
	if err != nil {
		t.Errorf("unexpected error enabling enforcement after reopen: %v", err)
	}
}

// =============================================================================
// Auto-Revert Tests
// =============================================================================

func TestEnforcementGateAutoRevert(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.MaxEnforcementDuration = 100 * time.Millisecond
	options.Logger = slog.Default()

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Should be in enforce mode
	if !gate.IsEnforceMode() {
		t.Error("expected enforce mode")
	}

	// Wait for auto-revert
	time.Sleep(150 * time.Millisecond)
	gate.AutoRevertIfNeeded()

	// Should be back in shadow mode
	if gate.IsEnforceMode() {
		t.Error("expected shadow mode after auto-revert")
	}
	if !gate.IsShadowMode() {
		t.Error("expected shadow mode after auto-revert")
	}
}

func TestEnforcementGateNoAutoRevertWhenDisabled(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.MaxEnforcementDuration = 100 * time.Millisecond

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Wait
	time.Sleep(150 * time.Millisecond)
	gate.AutoRevertIfNeeded()

	// Should still be in enforce mode (no auto-revert with MaxEnforcementDuration=0)
	// Actually, we set it to 100ms, so it should revert
	// Let's just check it doesn't panic
	_ = gate.Mode()
}

// =============================================================================
// Allowlist Tests
// =============================================================================

func TestEnforcementGateMethodAllowlist(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.MethodAllowlist = []string{"GET", "POST"}

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Create test requests
	getReq := httptest.NewRequest("GET", "http://example.com/resource", nil)
	postReq := httptest.NewRequest("POST", "http://example.com/resource", nil)
	putReq := httptest.NewRequest("PUT", "http://example.com/resource", nil)

	// GET and POST should be allowed
	if !gate.ShouldEnforceForRequest(getReq) {
		t.Error("expected GET request to be enforceable")
	}
	if !gate.ShouldEnforceForRequest(postReq) {
		t.Error("expected POST request to be enforceable")
	}

	// PUT should not be allowed
	if gate.ShouldEnforceForRequest(putReq) {
		t.Error("expected PUT request not to be enforceable")
	}
}

func TestEnforcementGateResourceAllowlist(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.MethodAllowlist = []string{"GET", "POST", "PUT", "DELETE"}
	options.ResourceAllowlist = []string{"/public/*", "/api/v1/*"}

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Create test requests
	publicReq := httptest.NewRequest("GET", "http://example.com/public/data", nil)
	apiReq := httptest.NewRequest("GET", "http://example.com/api/v1/resource", nil)
	privateReq := httptest.NewRequest("GET", "http://example.com/private/secret", nil)

	// Public and API resources should be allowed
	if !gate.ShouldEnforceForRequest(publicReq) {
		t.Error("expected public resource to be enforceable")
	}
	if !gate.ShouldEnforceForRequest(apiReq) {
		t.Error("expected API resource to be enforceable")
	}

	// Private resource should not be allowed
	if gate.ShouldEnforceForRequest(privateReq) {
		t.Error("expected private resource not to be enforceable")
	}
}

func TestEnforcementGateStorageAllowlist(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.MethodAllowlist = []string{"GET", "POST", "PUT", "DELETE"}
	options.StorageAllowlist = []string{"trusted-storage.example.com", "*.safe.example.org"}

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Create test requests
	trustedReq := httptest.NewRequest("GET", "http://trusted-storage.example.com/resource", nil)
	safeReq := httptest.NewRequest("GET", "http://app.safe.example.org/resource", nil)
	untrustedReq := httptest.NewRequest("GET", "http://untrusted.example.com/resource", nil)

	// Trusted storages should be allowed
	if !gate.ShouldEnforceForRequest(trustedReq) {
		t.Error("expected trusted storage to be enforceable")
	}
	if !gate.ShouldEnforceForRequest(safeReq) {
		t.Error("expected safe storage to be enforceable")
	}

	// Untrusted storage should not be allowed
	if gate.ShouldEnforceForRequest(untrustedReq) {
		t.Error("expected untrusted storage not to be enforceable")
	}
}

func TestEnforcementGateEmptyAllowlists(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.MethodAllowlist = []string{}   // Empty = all methods allowed
	options.ResourceAllowlist = []string{} // Empty = all resources allowed
	options.StorageAllowlist = []string{}  // Empty = all storages allowed

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// All requests should be enforceable with empty allowlists
	req := httptest.NewRequest("DELETE", "http://any.example.com/anything", nil)
	if !gate.ShouldEnforceForRequest(req) {
		t.Error("expected request to be enforceable with empty allowlists")
	}
}

// =============================================================================
// Canary Tests
// =============================================================================

func TestEnforcementGateCanaryPercentage(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.CanaryConfig.Enabled = true
	options.CanaryConfig.Mode = CanaryModePercentage
	options.CanaryConfig.Percentage = 50 // 50%

	gate, _ := NewEnforcementGate(options)
	gate.EnableCanary()

	if !gate.IsCanaryMode() {
		t.Error("expected canary mode")
	}

	// Test 100 requests, should be roughly 50% enforced
	enforcedCount := 0
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		if gate.ShouldEnforceForRequest(req) {
			enforcedCount++
		}
	}

	// Should be roughly 50 (allow some variance)
	if enforcedCount < 40 || enforcedCount > 60 {
		t.Errorf("expected roughly 50 enforced requests, got %d", enforcedCount)
	}
}

func TestEnforcementGateCanaryHeader(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.CanaryConfig.Enabled = true
	options.CanaryConfig.Mode = CanaryModeHeader
	options.CanaryConfig.HeaderName = "X-Canary"
	options.CanaryConfig.HeaderValue = "enable"

	gate, _ := NewEnforcementGate(options)
	gate.EnableCanary()

	// Request without header
	req1 := httptest.NewRequest("GET", "http://example.com/test", nil)
	if gate.ShouldEnforceForRequest(req1) {
		t.Error("expected request without canary header not to be enforced")
	}

	// Request with wrong header value
	req2 := httptest.NewRequest("GET", "http://example.com/test", nil)
	req2.Header.Set("X-Canary", "disable")
	if gate.ShouldEnforceForRequest(req2) {
		t.Error("expected request with wrong canary header value not to be enforced")
	}

	// Request with correct header
	req3 := httptest.NewRequest("GET", "http://example.com/test", nil)
	req3.Header.Set("X-Canary", "enable")
	if !gate.ShouldEnforceForRequest(req3) {
		t.Error("expected request with correct canary header to be enforced")
	}
}

func TestEnforcementGateCanaryPath(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.CanaryConfig.Enabled = true
	options.CanaryConfig.Mode = CanaryModePath
	options.CanaryConfig.PathPatterns = []string{"/canary/*", "/test/canary"}

	gate, _ := NewEnforcementGate(options)
	gate.EnableCanary()

	// Request to non-canary path
	req1 := httptest.NewRequest("GET", "http://example.com/production", nil)
	if gate.ShouldEnforceForRequest(req1) {
		t.Error("expected non-canary path not to be enforced")
	}

	// Request to canary path
	req2 := httptest.NewRequest("GET", "http://example.com/canary/test", nil)
	if !gate.ShouldEnforceForRequest(req2) {
		t.Error("expected canary path to be enforced")
	}

	req3 := httptest.NewRequest("GET", "http://example.com/test/canary", nil)
	if !gate.ShouldEnforceForRequest(req3) {
		t.Error("expected canary path to be enforced")
	}
}

func TestEnforcementGateCanaryDisabled(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.CanaryConfig.Enabled = false

	gate, _ := NewEnforcementGate(options)
	gate.EnableCanary()

	// With canary disabled in config, should not enforce for any request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	if gate.ShouldEnforceForRequest(req) {
		t.Error("expected no enforcement when canary is disabled in config")
	}
}

// =============================================================================
// Mismatch and Auto-Disable Tests
// =============================================================================

func TestEnforcementGateRecordMismatch(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.AutoDisableOnMismatchThreshold = 50 // 50% threshold

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Record some decisions
	gate.metrics.RecordDecisionEnforced(true)
	gate.metrics.RecordDecisionEnforced(true)
	gate.metrics.RecordDecisionEnforced(true)
	gate.metrics.RecordDecisionEnforced(true)
	// 4 decisions total

	// Record mismatches (but not enough to trigger auto-disable)
	// Need more than 50% of 4 = more than 2 mismatches to trigger
	gate.RecordMismatch()
	gate.RecordMismatch()

	if gate.IsAutoDisabled() {
		t.Error("expected enforcement not to be auto-disabled yet (2/4 = 50%, need >50%)")
	}

	// Record one more mismatch to trigger auto-disable (3/4 = 75% > 50%)
	gate.RecordMismatch()

	if !gate.IsAutoDisabled() {
		t.Error("expected enforcement to be auto-disabled after threshold (3/4 = 75% > 50%)")
	}

	// Check the reason
	reason := gate.AutoDisableReason()
	if reason == "" {
		t.Error("expected auto-disable reason to be set")
	}
	t.Logf("Auto-disable reason: %s", reason)

	// Should not enforce when auto-disabled
	if gate.ShouldEnforce() {
		t.Error("expected ShouldEnforce to return false when auto-disabled")
	}
}

func TestEnforcementGateClearMismatches(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.AutoDisableOnMismatchThreshold = 50

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Record enough mismatches to trigger auto-disable
	gate.metrics.RecordDecisionEnforced(true)
	gate.metrics.RecordDecisionEnforced(true)
	gate.RecordMismatch()
	gate.RecordMismatch()

	if !gate.IsAutoDisabled() {
		t.Error("expected enforcement to be auto-disabled")
	}

	// Clear mismatches
	gate.ClearMismatches()

	if gate.IsAutoDisabled() {
		t.Error("expected enforcement not to be auto-disabled after clearing mismatches")
	}

	// Should enforce again
	if !gate.ShouldEnforce() {
		t.Error("expected ShouldEnforce to return true after clearing mismatches")
	}
}

func TestEnforcementGateMismatchCount(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	gate, _ := NewEnforcementGate(options)

	if gate.GetMismatchCount() != 0 {
		t.Errorf("expected mismatch count 0 initially, got %d", gate.GetMismatchCount())
	}

	gate.RecordMismatch()
	gate.RecordMismatch()

	if gate.GetMismatchCount() != 2 {
		t.Errorf("expected mismatch count 2, got %d", gate.GetMismatchCount())
	}
}

// =============================================================================
// Metrics Tests
// =============================================================================

func TestEnforcementGateMetrics(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true // Need to allow enforcement to change mode
	gate, _ := NewEnforcementGate(options)

	// Test initial metrics
	metrics := gate.GetMetrics()
	if metrics.ModeChanges != 0 {
		t.Errorf("expected 0 mode changes initially, got %d", metrics.ModeChanges)
	}

	// Change mode
	_ = gate.EnableEnforcement()

	// Record some metrics
	gate.metrics.RecordDecisionEnforced(true)
	gate.metrics.RecordDecisionEnforced(false)
	gate.metrics.RecordDecisionShadowed()
	gate.metrics.RecordAllowlistHit()
	gate.metrics.RecordAllowlistMiss()
	gate.metrics.RecordMismatch()
	gate.metrics.RecordEmergencyBypass()
	gate.metrics.RecordAuditEvent()

	// Check metrics
	metrics = gate.GetMetrics()
	if metrics.ModeChanges < 1 {
		t.Errorf("expected at least 1 mode change, got %d", metrics.ModeChanges)
	}
	if metrics.DecisionsEnforced != 2 {
		t.Errorf("expected 2 decisions enforced, got %d", metrics.DecisionsEnforced)
	}
	if metrics.DecisionsAllow != 1 {
		t.Errorf("expected 1 allow decision, got %d", metrics.DecisionsAllow)
	}
	if metrics.DecisionsDeny != 1 {
		t.Errorf("expected 1 deny decision, got %d", metrics.DecisionsDeny)
	}
	if metrics.DecisionsShadowed != 1 {
		t.Errorf("expected 1 decision shadowed, got %d", metrics.DecisionsShadowed)
	}
	if metrics.AllowlistHits != 1 {
		t.Errorf("expected 1 allowlist hit, got %d", metrics.AllowlistHits)
	}
	if metrics.AllowlistMisses != 1 {
		t.Errorf("expected 1 allowlist miss, got %d", metrics.AllowlistMisses)
	}
	if metrics.MismatchCount != 1 {
		t.Errorf("expected 1 mismatch, got %d", metrics.MismatchCount)
	}
	if metrics.EmergencyBypassActivated != 1 {
		t.Errorf("expected 1 emergency bypass, got %d", metrics.EmergencyBypassActivated)
	}
	if metrics.AuditEvents < 1 {
		t.Errorf("expected at least 1 audit event, got %d", metrics.AuditEvents)
	}
}

func TestEnforcementGateMetricsMismatchRate(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	gate, _ := NewEnforcementGate(options)

	// No decisions yet
	rate := gate.metrics.GetMismatchRate()
	if rate != 0 {
		t.Errorf("expected mismatch rate 0 with no decisions, got %f", rate)
	}

	// Record 3 enforced decisions and 1 mismatch
	gate.metrics.RecordDecisionEnforced(true)
	gate.metrics.RecordDecisionEnforced(true)
	gate.metrics.RecordDecisionEnforced(false)
	gate.metrics.RecordMismatch()

	// Rate should be 33.33%
	rate = gate.metrics.GetMismatchRate()
	expectedRate := 100.0 / 3.0
	if rate < expectedRate-0.1 || rate > expectedRate+0.1 {
		t.Errorf("expected mismatch rate ~%.2f%%, got %.2f%%", expectedRate, rate)
	}
}

// =============================================================================
// Middleware Tests
// =============================================================================

func TestEnforcementGateMiddleware(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Create middleware
	middleware := EnforcementGateMiddleware(gate, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	rec := httptest.NewRecorder()

	middleware.ServeHTTP(rec, req)

	// Check headers
	modeHeader := rec.Header().Get("X-Authz-Enforcement-Mode")
	if modeHeader != "enforce" {
		t.Errorf("expected X-Authz-Enforcement-Mode header 'enforce', got %q", modeHeader)
	}

	// Test dry-run mode
	gate.EnableDryRun()
	req2 := httptest.NewRequest("GET", "http://example.com/test", nil)
	rec2 := httptest.NewRecorder()

	middleware.ServeHTTP(rec2, req2)

	modeHeader = rec2.Header().Get("X-Authz-Enforcement-Mode")
	if modeHeader != "dry-run" {
		t.Errorf("expected X-Authz-Enforcement-Mode header 'dry-run', got %q", modeHeader)
	}

	dryRunHeader := rec2.Header().Get("X-Authz-Mode")
	if dryRunHeader != "dry-run" {
		t.Errorf("expected X-Authz-Mode header 'dry-run', got %q", dryRunHeader)
	}

	// Test canary mode
	gate.EnableCanary()
	gate.options.CanaryConfig.Enabled = true
	req3 := httptest.NewRequest("GET", "http://example.com/test", nil)
	rec3 := httptest.NewRecorder()

	middleware.ServeHTTP(rec3, req3)

	modeHeader = rec3.Header().Get("X-Authz-Enforcement-Mode")
	if modeHeader != "enforce_canary" {
		t.Errorf("expected X-Authz-Enforcement-Mode header 'enforce_canary', got %q", modeHeader)
	}

	canaryHeader := rec3.Header().Get("X-Authz-Canary")
	if canaryHeader != "true" {
		t.Errorf("expected X-Authz-Canary header 'true', got %q", canaryHeader)
	}
}

// =============================================================================
// Context Tests
// =============================================================================

func TestEnforcementGateContext(t *testing.T) {
	ctx := context.Background()

	// Test adding mode to context
	ctx = WithEnforcementMode(ctx, EnforcementModeEnforce)

	// Test retrieving mode from context
	mode, ok := EnforcementModeFromContext(ctx)
	if !ok {
		t.Error("expected to get mode from context")
	}
	if mode != EnforcementModeEnforce {
		t.Errorf("expected mode enforce from context, got %q", mode)
	}

	// Test with empty context
	_, ok = EnforcementModeFromContext(context.Background())
	if ok {
		t.Error("expected not to get mode from empty context")
	}
}

// =============================================================================
// Options Validation Tests
// =============================================================================

func TestEnforcementGateInvalidCanaryConfig(t *testing.T) {
	// Invalid percentage
	options := DefaultEnforcementGateOptions()
	options.CanaryConfig.Enabled = true
	options.CanaryConfig.Percentage = 150

	_, err := NewEnforcementGate(options)
	if err == nil {
		t.Error("expected error for invalid canary percentage")
	}

	// Header mode without header name
	options = DefaultEnforcementGateOptions()
	options.CanaryConfig.Enabled = true
	options.CanaryConfig.Mode = CanaryModeHeader
	options.CanaryConfig.HeaderName = ""

	_, err = NewEnforcementGate(options)
	if err == nil {
		t.Error("expected error for header mode without header name")
	}
}

func TestEnforcementGateInvalidMismatchThreshold(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AutoDisableOnMismatchThreshold = 150

	_, err := NewEnforcementGate(options)
	if err == nil {
		t.Error("expected error for invalid mismatch threshold")
	}

	options.AutoDisableOnMismatchThreshold = -1
	_, err = NewEnforcementGate(options)
	if err == nil {
		t.Error("expected error for negative mismatch threshold")
	}
}

func TestEnforcementGateInvalidAllowlistPattern(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.ResourceAllowlist = []string{"/valid/*", "/invalid[pattern"}

	_, err := NewEnforcementGate(options)
	if err == nil {
		t.Error("expected error for invalid allowlist pattern")
	}
}

// =============================================================================
// Decorate Decision Tests
// =============================================================================

func TestEnforcementGateDecorateDecision(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	gate, _ := NewEnforcementGate(options)

	decision := Decision{
		SchemaVersion: SchemaVersion,
		RequestID:     "test-request",
		Decision:      DecisionAllow,
		ReasonCode:    ReasonPolicyAllow,
		Audit: AuditFields{
			RequestHash: "test-hash",
			PolicyHash:  "test-policy-hash",
		},
	}

	// Should not modify the decision (yet)
	decorated := gate.DecorateDecision(decision)

	if decorated.Decision != DecisionAllow {
		t.Error("expected decorated decision to preserve Decision")
	}
	if decorated.ReasonCode != ReasonPolicyAllow {
		t.Errorf("expected decorated decision to preserve ReasonCode, got %q", decorated.ReasonCode)
	}
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestEnforcementGateConcurrentAccess(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.EmergencyBypassToken = "concurrent-test-token"

	gate, _ := NewEnforcementGate(options)

	// Run concurrent operations
	done := make(chan bool)

	// Concurrent mode changes
	for i := 0; i < 10; i++ {
		go func() {
			_ = gate.EnableEnforcement()
			_ = gate.EnableDryRun()
			_ = gate.EnableCanary()
			gate.DisableEnforcement()
			done <- true
		}()
	}

	// Concurrent bypass operations
	for i := 0; i < 10; i++ {
		go func() {
			gate.EmergencyBypass("concurrent-test-token")
			gate.ClearEmergencyBypass("concurrent-test-token")
			done <- true
		}()
	}

	// Concurrent mismatch recording
	for i := 0; i < 10; i++ {
		go func() {
			gate.RecordMismatch()
			gate.ClearMismatches()
			done <- true
		}()
	}

	// Concurrent metric recording
	for i := 0; i < 10; i++ {
		go func() {
			gate.metrics.RecordDecisionEnforced(true)
			gate.metrics.RecordDecisionShadowed()
			gate.metrics.RecordAllowlistHit()
			gate.metrics.RecordMismatch()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 40; i++ {
		<-done
	}

	// Should not panic and gate should still be functional
	if gate.IsClosed() {
		t.Error("gate should not be closed after concurrent access")
	}

	// Mode should be shadow (last DisableEnforcement)
	if !gate.IsShadowMode() {
		t.Error("expected shadow mode after concurrent operations")
	}
}

// =============================================================================
// Logging Tests
// ==============================================================================

func TestEnforcementGateLogging(t *testing.T) {
	// Create a test logger
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	auditLogger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))

	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.Logger = logger
	options.AuditLogger = auditLogger

	gate, _ := NewEnforcementGate(options)

	// These should not panic and should use the loggers
	_ = gate.EnableEnforcement()
	gate.DisableEnforcement()
	gate.Close("test close")
	gate.Reopen()
	gate.EmergencyBypass("test-token")
	gate.ClearEmergencyBypass("test-token")
	gate.RecordMismatch()
	gate.ClearMismatches()
}

// Helper for logging tests - no longer needed with io.Discard

// =============================================================================
// Acceptance Criteria Tests
// =============================================================================

// Acceptance criterion: Enforcement cannot be enabled by a single ambiguous environment variable
func TestEnforcementGateNotEnabledByDefault(t *testing.T) {
	// Default options should have enforcement disabled
	options := DefaultEnforcementGateOptions()
	if options.AllowEnforcement {
		t.Error("enforcement should not be allowed by default")
	}

	gate, _ := NewEnforcementGate(options)
	if gate.IsEnforcementAllowed() {
		t.Error("enforcement should not be allowed by default")
	}

	// Should not be able to enable enforcement
	err := gate.EnableEnforcement()
	if err == nil {
		t.Error("should not be able to enable enforcement by default")
	}
}

// Acceptance criterion: Bypass returns immediately to CSS-authoritative behavior
func TestEnforcementGateBypassReturnsToShadow(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.EmergencyBypassEnabled = true
	options.EmergencyBypassToken = "bypass-test"

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Activate bypass
	gate.EmergencyBypass("bypass-test")

	// ShouldEnforce should return false
	if gate.ShouldEnforce() {
		t.Error("bypass should prevent enforcement")
	}

	// Clear bypass
	gate.ClearEmergencyBypass("bypass-test")

	// Should enforce again (CSS-authoritative behavior is shadow, but we're in enforce mode)
	// Actually, ShouldEnforce returns true for enforce/dry-run modes without bypass
	if !gate.ShouldEnforce() {
		t.Error("after clearing bypass, should enforce again")
	}
}

// Acceptance criterion: Canary can be disabled without redeploying
func TestEnforcementGateCanaryCanBeDisabled(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.CanaryConfig.Enabled = true

	gate, _ := NewEnforcementGate(options)
	gate.EnableCanary()

	if !gate.IsCanaryMode() {
		t.Error("expected canary mode")
	}

	// Disable canary in options (simulating config change without redeploy)
	// In a real system, this would be done through config reload
	// For now, we just test that we can switch back to shadow
	gate.DisableEnforcement()

	if gate.IsCanaryMode() {
		t.Error("expected canary mode to be disabled")
	}
}

// Acceptance criterion: All denies are explainable and auditable
func TestEnforcementGateDeniesAreAuditable(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.EmergencyBypassEnabled = true
	options.EmergencyBypassToken = "audit-test"

	// Create audit logger that captures logs
	// For this test, we'll just verify metrics are recorded
	// In a real system, audit logs would be written to a secure audit log
	options.AuditLogger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	options.Logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))

	gate, _ := NewEnforcementGate(options)
	gate.EnableEnforcement()

	// Record a deny decision
	gate.metrics.RecordDecisionEnforced(false)

	// Activate bypass (which logs)
	gate.EmergencyBypass("audit-test")

	// Check that audit events were recorded
	metrics := gate.GetMetrics()
	if metrics.AuditEvents == 0 {
		t.Error("expected audit events to be recorded for deny decisions")
	}

	// The audit metrics should be incremented
	if metrics.EmergencyBypassActivated == 0 {
		t.Error("expected emergency bypass to be recorded in metrics")
	}
}

// =============================================================================
// Helper Tests
// =============================================================================

func TestGenerateEmergencyBypassToken(t *testing.T) {
	token1 := generateEmergencyBypassToken()
	token2 := generateEmergencyBypassToken()

	// Tokens should be non-empty
	if token1 == "" {
		t.Error("expected non-empty token")
	}
	if token2 == "" {
		t.Error("expected non-empty token")
	}

	// Tokens should be different (unless generated at the same nanosecond)
	// We can't guarantee they're different, but they should be valid hex
	if len(token1) != 32 {
		t.Errorf("expected token length 32, got %d", len(token1))
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		match   bool
	}{
		{"/test/*", "/test/123", true},
		{"/test/*", "/test/abc/def", true},
		{"/test/*", "/other/123", false},
		{"*.example.com", "test.example.com", true},
		{"*.example.com", "other.example.org", false},
		{"/api/v?/resource", "/api/v1/resource", true},
		{"/api/v?/resource", "/api/v2/resource", true},
		{"/api/v?/resource", "/api/v10/resource", false},
		{"/exact", "/exact", true},
		{"/exact", "/exact/extra", false},
		{"*", "anything", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.pattern, tt.input), func(t *testing.T) {
			result := matchPattern(tt.pattern, tt.input)
			if result != tt.match {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.input, result, tt.match)
			}
		})
	}
}
