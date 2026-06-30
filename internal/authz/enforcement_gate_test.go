// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestEnforcementGateCreation tests creating an enforcement gate
func TestEnforcementGateCreation(t *testing.T) {
	gate, err := NewEnforcementGate(DefaultEnforcementGateOptions())
	if err != nil {
		t.Fatalf("failed to create enforcement gate: %v", err)
	}
	if gate == nil {
		t.Fatal("enforcement gate is nil")
	}
}

// TestEnforcementGateDefaultOptions tests default options
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
	if options.Logger != nil {
		t.Error("expected logger to be nil by default")
	}
}

// TestEnforcementGateInitialMode tests the initial mode
func TestEnforcementGateInitialMode(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.InitialMode = EnforcementModeShadow

	gate, _ := NewEnforcementGate(options)
	if gate.Mode() != EnforcementModeShadow {
		t.Errorf("expected mode shadow, got %q", gate.Mode())
	}

	options.InitialMode = EnforcementModeEnforce
	gate2, _ := NewEnforcementGate(options)
	// Even if we set enforce as initial mode, it won't be enforced if not allowed
	// But the mode should still be set
	if gate2.Mode() != EnforcementModeEnforce {
		t.Errorf("expected mode enforce, got %q", gate2.Mode())
	}
}

// TestEnforcementGateModeChecks tests mode check methods
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

	// Test enforce mode
	gate.EnableEnforcement()
	if gate.IsShadowMode() {
		t.Error("expected not shadow mode after enabling enforcement")
	}
	if !gate.IsEnforceMode() {
		t.Error("expected enforce mode")
	}

	// Test dry-run mode
	gate.EnableDryRun()
	if gate.IsEnforceMode() {
		t.Error("expected not enforce mode after enabling dry-run")
	}
	if !gate.IsDryRunMode() {
		t.Error("expected dry-run mode")
	}

	// Back to shadow
	gate.DisableEnforcement()
	if !gate.IsShadowMode() {
		t.Error("expected shadow mode after disabling enforcement")
	}
}

// TestEnforcementGateEnforcementNotAllowed tests error when enforcement not allowed
func TestEnforcementGateEnforcementNotAllowed(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = false // Default is false anyway

	gate, _ := NewEnforcementGate(options)

	// Try to enable enforcement
	err := gate.EnableEnforcement()
	if err == nil {
		t.Fatal("expected error when enabling enforcement not allowed, got nil")
	}
	if !isEnforcementNotAllowedError(err) {
		t.Errorf("expected enforcement not allowed error, got %v", err)
	}

	// Try to enable dry-run
	err = gate.EnableDryRun()
	if err == nil {
		t.Fatal("expected error when enabling dry-run not allowed, got nil")
	}
}

func isEnforcementNotAllowedError(err error) bool {
	return err.Error() == "enforcement not allowed: enforcement mode not configured as allowed"
}

// TestEnforcementGateSetMode tests setting mode directly
func TestEnforcementGateSetMode(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true

	gate, _ := NewEnforcementGate(options)

	// Set to enforce
	err := gate.SetMode(EnforcementModeEnforce)
	if err != nil {
		t.Fatalf("failed to set mode to enforce: %v", err)
	}
	if gate.Mode() != EnforcementModeEnforce {
		t.Errorf("expected mode enforce, got %q", gate.Mode())
	}

	// Set to dry-run
	err = gate.SetMode(EnforcementModeDryRun)
	if err != nil {
		t.Fatalf("failed to set mode to dry-run: %v", err)
	}
	if gate.Mode() != EnforcementModeDryRun {
		t.Errorf("expected mode dry-run, got %q", gate.Mode())
	}

	// Set to shadow
	err = gate.SetMode(EnforcementModeShadow)
	if err != nil {
		t.Fatalf("failed to set mode to shadow: %v", err)
	}
	if gate.Mode() != EnforcementModeShadow {
		t.Errorf("expected mode shadow, got %q", gate.Mode())
	}
}

// TestEnforcementGateEmergencyBypass tests emergency bypass functionality
func TestEnforcementGateEmergencyBypass(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.EmergencyBypassEnabled = true
	options.EmergencyBypassToken = "test-token-123"

	gate, _ := NewEnforcementGate(options)

	// Initially, no bypass active
	if gate.IsEmergencyBypassActive() {
		t.Error("expected no emergency bypass initially")
	}

	// Activate bypass with correct token
	success := gate.EmergencyBypass("test-token-123")
	if !success {
		t.Error("expected emergency bypass to succeed with correct token")
	}
	if !gate.IsEmergencyBypassActive() {
		t.Error("expected emergency bypass to be active after activation")
	}

	// Activate bypass with wrong token
	success = gate.EmergencyBypass("wrong-token")
	if success {
		t.Error("expected emergency bypass to fail with wrong token")
	}

	// Clear bypass
	gate.ClearEmergencyBypass("test-token-123")
	if gate.IsEmergencyBypassActive() {
		t.Error("expected emergency bypass to be inactive after clearing")
	}
}

// TestEnforcementGateEmergencyBypassDisabled tests when bypass is disabled
func TestEnforcementGateEmergencyBypassDisabled(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.EmergencyBypassEnabled = false

	gate, _ := NewEnforcementGate(options)

	// Bypass should fail when disabled
	success := gate.EmergencyBypass("any-token")
	if success {
		t.Error("expected emergency bypass to fail when disabled")
	}
}

// TestEnforcementGateClose tests closing the gate
func TestEnforcementGateClose(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true

	gate, _ := NewEnforcementGate(options)

	// Gate should be open initially
	if gate.IsClosed() {
		t.Error("expected gate to be open initially")
	}

	// Close the gate
	gate.Close("test closure")
	if !gate.IsClosed() {
		t.Error("expected gate to be closed")
	}
	if gate.CloseReason() != "test closure" {
		t.Errorf("expected close reason 'test closure', got %q", gate.CloseReason())
	}

	// Try to change mode while closed
	err := gate.SetMode(EnforcementModeEnforce)
	if err == nil {
		t.Fatal("expected error when setting mode on closed gate, got nil")
	}

	// Reopen the gate
	gate.Reopen()
	if gate.IsClosed() {
		t.Error("expected gate to be open after reopening")
	}
	if gate.CloseReason() != "" {
		t.Errorf("expected empty close reason after reopening, got %q", gate.CloseReason())
	}

	// Now mode change should work
	err = gate.SetMode(EnforcementModeEnforce)
	if err != nil {
		t.Fatalf("failed to set mode after reopening: %v", err)
	}
}

// TestEnforcementGateShouldEnforce tests ShouldEnforce logic
func TestEnforcementGateShouldEnforce(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.EmergencyBypassToken = "test-bypass-token" // Set a known token

	gate, _ := NewEnforcementGate(options)

	// Shadow mode - should not enforce
	if gate.ShouldEnforce() {
		t.Error("expected not to enforce in shadow mode")
	}

	// Enforce mode - should enforce
	gate.EnableEnforcement()
	if !gate.ShouldEnforce() {
		t.Error("expected to enforce in enforce mode")
	}

	// Dry-run mode - should enforce
	gate.EnableDryRun()
	if !gate.ShouldEnforce() {
		t.Error("expected to enforce in dry-run mode")
	}

	// With emergency bypass - should not enforce
	gate.EmergencyBypass("test-bypass-token")
	if gate.ShouldEnforce() {
		t.Error("expected not to enforce with emergency bypass active")
	}

	// Clear bypass
	gate.ClearEmergencyBypass("test-bypass-token")
	if !gate.ShouldEnforce() {
		t.Error("expected to enforce after clearing bypass")
	}

	// Close gate - should not enforce
	gate.Close("test")
	if gate.ShouldEnforce() {
		t.Error("expected not to enforce when gate is closed")
	}
}

// TestEnforcementGateDryRunHeader tests dry-run header logic
func TestEnforcementGateDryRunHeader(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true

	gate, _ := NewEnforcementGate(options)

	// Shadow mode - no dry-run header
	if gate.ShouldAddDryRunHeader() {
		t.Error("expected no dry-run header in shadow mode")
	}

	// Enforce mode - no dry-run header
	gate.EnableEnforcement()
	if gate.ShouldAddDryRunHeader() {
		t.Error("expected no dry-run header in enforce mode")
	}

	// Dry-run mode - should add header
	gate.EnableDryRun()
	if !gate.ShouldAddDryRunHeader() {
		t.Error("expected dry-run header in dry-run mode")
	}

	// Closed gate - no header
	gate.Close("test")
	if gate.ShouldAddDryRunHeader() {
		t.Error("expected no dry-run header when gate is closed")
	}
}

// TestEnforcementGateAutoRevert tests auto-revert functionality
func TestEnforcementGateAutoRevert(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.MaxEnforcementDuration = 10 * time.Millisecond // Very short duration

	gate, _ := NewEnforcementGate(options)

	// Enable enforcement
	gate.EnableEnforcement()
	if !gate.IsEnforceMode() {
		t.Fatal("expected enforce mode after enabling")
	}

	// Wait for auto-revert
	time.Sleep(20 * time.Millisecond)

	// Check and auto-revert
	gate.AutoRevertIfNeeded()

	// Should have reverted to shadow
	if !gate.IsShadowMode() {
		t.Error("expected shadow mode after auto-revert")
	}
}

// TestEnforcementGateMiddleware tests the HTTP middleware
func TestEnforcementGateMiddleware(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true

	gate, _ := NewEnforcementGate(options)

	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with middleware
	wrapped := EnforcementGateMiddleware(gate, handler)

	// Test in shadow mode
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	// Should have enforcement mode header
	if rr.Header().Get("X-Authz-Enforcement-Mode") != "shadow" {
		t.Errorf("expected shadow mode header, got %q", rr.Header().Get("X-Authz-Enforcement-Mode"))
	}

	// Test in enforce mode
	gate.EnableEnforcement()
	req2 := httptest.NewRequest("GET", "/test", nil)
	rr2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr2, req2)

	if rr2.Header().Get("X-Authz-Enforcement-Mode") != "enforce" {
		t.Errorf("expected enforce mode header, got %q", rr2.Header().Get("X-Authz-Enforcement-Mode"))
	}

	// Test in dry-run mode
	gate.EnableDryRun()
	req3 := httptest.NewRequest("GET", "/test", nil)
	rr3 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr3, req3)

	if rr3.Header().Get("X-Authz-Enforcement-Mode") != "dry-run" {
		t.Errorf("expected dry-run mode header, got %q", rr3.Header().Get("X-Authz-Enforcement-Mode"))
	}
	if rr3.Header().Get("X-Authz-Mode") != "dry-run" {
		t.Errorf("expected dry-run header, got %q", rr3.Header().Get("X-Authz-Mode"))
	}
}

// TestEnforcementGateContext tests context utilities
func TestEnforcementGateContext(t *testing.T) {
	ctx := context.Background()

	// Initially, no mode in context
	_, ok := EnforcementModeFromContext(ctx)
	if ok {
		t.Error("expected no mode in context initially")
	}

	// Add mode to context
	ctx = WithEnforcementMode(ctx, EnforcementModeEnforce)
	mode, ok := EnforcementModeFromContext(ctx)
	if !ok {
		t.Error("expected mode in context after setting")
	}
	if mode != EnforcementModeEnforce {
		t.Errorf("expected enforce mode, got %q", mode)
	}
}

// TestEnforcementGateDecorateDecision tests decision decoration
func TestEnforcementGateDecorateDecision(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	gate, _ := NewEnforcementGate(options)

	decision := Decision{
		SchemaVersion: SchemaVersion,
		RequestID:     "test-request",
		Decision:      DecisionAllow,
		ReasonCode:    ReasonPolicyAllow,
	}

	// Decorate should not modify the decision currently
	// (since Decision doesn't have a Metadata field)
	decorated := gate.DecorateDecision(decision)
	if decorated != decision {
		t.Error("decorate decision should not modify decision currently")
	}
}

// TestEnforcementGateIsEnforcementAllowed tests IsEnforcementAllowed
func TestEnforcementGateIsEnforcementAllowed(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = false

	gate, _ := NewEnforcementGate(options)
	if gate.IsEnforcementAllowed() {
		t.Error("expected enforcement not allowed")
	}

	options.AllowEnforcement = true
	gate2, _ := NewEnforcementGate(options)
	if !gate2.IsEnforcementAllowed() {
		t.Error("expected enforcement allowed")
	}
}

// TestEnforcementGateCheckEnforcementDuration tests duration checking
func TestEnforcementGateCheckEnforcementDuration(t *testing.T) {
	options := DefaultEnforcementGateOptions()
	options.AllowEnforcement = true
	options.MaxEnforcementDuration = 100 * time.Millisecond

	gate, _ := NewEnforcementGate(options)

	// Not in enforcement mode
	if gate.CheckEnforcementDuration() {
		t.Error("expected false when not in enforcement mode")
	}

	// Enable enforcement
	gate.EnableEnforcement()

	// Just enabled, should not have exceeded
	if gate.CheckEnforcementDuration() {
		t.Error("expected false when just enabled")
	}

	// Wait and check
	time.Sleep(150 * time.Millisecond)
	if !gate.CheckEnforcementDuration() {
		t.Error("expected true after duration exceeded")
	}
}
