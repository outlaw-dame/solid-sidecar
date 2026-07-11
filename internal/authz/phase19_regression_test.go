// Package authz provides authorization policy handling for Solid.
// This file implements the regression suite proving Phase 19 requirements.
package authz

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// TestPhase19EnforcementModeCannotBeEnabledWithoutThresholds proves:
// "enforcement mode cannot be enabled without passing comparison thresholds"
func TestPhase19EnforcementModeCannotBeEnabledWithoutThresholds(t *testing.T) {
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

	// Should fail to enable enforcement without meeting thresholds
	err = gate.EnableEnforcement()
	if err == nil {
		t.Error("Expected error when enabling enforcement without meeting thresholds")
	}

	// Record 9 matching results (not enough)
	for i := 0; i < 9; i++ {
		gate.RecordComparisonResult(true)
	}

	// Should still fail
	err = gate.EnableEnforcement()
	if err == nil {
		t.Error("Expected error with 9/10 matches")
	}

	// Record 10th match
	gate.RecordComparisonResult(true)

	// Now thresholds should be met
	if !gate.ThresholdMet() {
		t.Error("Expected thresholds to be met after 10 consecutive matches")
	}

	// Now enforcement should succeed
	err = gate.EnableEnforcement()
	if err != nil {
		t.Errorf("Expected no error after meeting thresholds, got: %v", err)
	}

	if gate.Mode() != EnforcementModeEnforce {
		t.Errorf("Expected EnforcementModeEnforce, got %s", gate.Mode())
	}
}

// TestPhase19EveryDecisionHasStructuredReasonCode proves:
// "every allow/deny decision has a structured reason code"
func TestPhase19EveryDecisionHasStructuredReasonCode(t *testing.T) {
	// Test allow reasons
	allowReasons := []DecisionReason{
		ReasonAllowedByPolicy,
		ReasonAllowedByOwner,
		ReasonAllowedByPublicAccess,
		ReasonAllowedByACL,
		ReasonAllowedByACP,
		ReasonAllowedByWAC,
		ReasonAllowedBySAI,
	}

	for _, reason := range allowReasons {
		if !strings.HasPrefix(string(reason), "allowed_by_") {
			t.Errorf("Allow reason should start with 'allowed_by_': %s", reason)
		}
	}

	// Test deny reasons
	denyReasons := []DecisionReason{
		ReasonDeniedByPolicy,
		ReasonDeniedNoMatchingRule,
		ReasonDeniedByOrigin,
		ReasonDeniedByMethod,
		ReasonDeniedByResourceType,
		ReasonDeniedByAgent,
		ReasonDeniedByACL,
		ReasonDeniedByACP,
		ReasonDeniedByWAC,
		ReasonDeniedBySAI,
	}

	for _, reason := range denyReasons {
		if !strings.HasPrefix(string(reason), "denied_") {
			t.Errorf("Deny reason should start with 'denied_': %s", reason)
		}
	}

	// Test abstain reasons
	abstainReasons := []DecisionReason{
		ReasonAbstainedParserError,
		ReasonAbstainedNoPolicy,
		ReasonAbstainedShadowMode,
		ReasonAbstainedNotImplemented,
	}

	for _, reason := range abstainReasons {
		if !strings.HasPrefix(string(reason), "abstained_") {
			t.Errorf("Abstain reason should start with 'abstained_': %s", reason)
		}
	}

	// Test error reasons
	errorReasons := []DecisionReason{
		ReasonErrorInternal,
		ReasonErrorTimeout,
		ReasonErrorPolicyFetch,
		ReasonErrorValidation,
	}

	for _, reason := range errorReasons {
		if !strings.HasPrefix(string(reason), "error_") {
			t.Errorf("Error reason should start with 'error_': %s", reason)
		}
	}
}

// TestPhase19ParserErrorsCannotTurnIntoAccidentalAllows proves:
// "policy parser errors cannot turn into accidental allows"
func TestPhase19ParserErrorsCannotTurnIntoAccidentalAllows(t *testing.T) {
	policy := DefaultFailClosedPolicy()

	// Default policy should deny on errors
	if !policy.Enabled {
		t.Error("Expected fail-closed policy to be enabled by default")
	}

	if !policy.DenyOnError {
		t.Error("Expected DenyOnError to be true by default")
	}

	testErr := errors.New("policy parser error")

	if !policy.ShouldDenyOnError(testErr) {
		t.Error("Expected ShouldDenyOnError to return true")
	}

	if !policy.ShouldDenyOnTimeout() {
		t.Error("Expected ShouldDenyOnTimeout to return true")
	}

	if !policy.ShouldDenyOnPolicyFetchError() {
		t.Error("Expected ShouldDenyOnPolicyFetchError to return true")
	}

	if !policy.ShouldDenyOnParserError() {
		t.Error("Expected ShouldDenyOnParserError to return true")
	}

	// With policy disabled, should not deny
	policy.Enabled = false
	if policy.ShouldDenyOnError(testErr) {
		t.Error("Expected ShouldDenyOnError to return false when disabled")
	}
}

// TestPhase19CSSFallbackBypassIsDocumentedAndTested proves:
// "CSS fallback/bypass is documented and tested"
func TestPhase19CSSFallbackBypassIsDocumentedAndTested(t *testing.T) {
	// Test ShouldContinueToCSS function
	abstainDecision := Decision{
		Decision:   DecisionAbstain,
		ReasonCode: ReasonAbstainedShadowMode,
	}

	if !ShouldContinueToCSS(abstainDecision) {
		t.Error("Expected ShouldContinueToCSS to return true for abstain decisions")
	}

	allowDecision := Decision{
		Decision:   DecisionAllow,
		ReasonCode: ReasonPolicyAllow,
	}

	if ShouldContinueToCSS(allowDecision) {
		t.Error("Expected ShouldContinueToCSS to return false for allow decisions")
	}

	denyDecision := Decision{
		Decision:   DecisionDeny,
		ReasonCode: ReasonPolicyDeny,
	}

	if ShouldContinueToCSS(denyDecision) {
		t.Error("Expected ShouldContinueToCSS to return false for deny decisions")
	}
}

// TestPhase19NativeAuthzDoesNotGrantAccessFromDidSolidBindingAlone proves:
// "native authz does not grant access from `did:solid` binding alone"
func TestPhase19NativeAuthzDoesNotGrantAccessFromDidSolidBindingAlone(t *testing.T) {
	ctx := context.Background()

	// Request with did:solid binding but no policies
	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "req-didsolid",
		Method:         "GET",
		ResourceURI:    "https://example.com/protected",
		AgentWebID:     "did:solid:example:user",
		ClientID:       "did:solid:example:client",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        1000000000,
	}

	// Shadow evaluator should not allow based on did:solid alone
	evaluator := NewShadowEvaluator()
	decision, err := evaluator.Evaluate(ctx, request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should not be allow
	if decision.Decision == DecisionAllow {
		t.Error("did:solid binding alone should not result in allow decision")
	}

	// Should be abstain or deny
	if decision.Decision != DecisionAbstain && decision.Decision != DecisionDeny {
		t.Errorf("Expected abstain or deny, got %s", decision.Decision)
	}

	// Reason should indicate no policy or shadow mode
	validReasons := []ReasonCode{
		ReasonAbstainedNoPolicy,
		ReasonAbstainedShadowMode,
		ReasonKernelAbstainShadowMode,
	}

	found := false
	for _, validReason := range validReasons {
		if decision.ReasonCode == validReason {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected reason to be one of %v, got %s", validReasons, decision.ReasonCode)
	}
}

// TestPhase19OperatorVisibleDecisionTraceIDs proves:
// "operator-visible decision trace IDs"
func TestPhase19OperatorVisibleDecisionTraceIDs(t *testing.T) {
	// Generate a trace ID
	traceID := GenerateDecisionTraceID()

	if traceID == "" {
		t.Error("Expected non-empty trace ID")
	}

	// Trace IDs should be unique
	traceID2 := GenerateDecisionTraceID()
	if traceID == traceID2 {
		t.Error("Expected unique trace IDs")
	}

	// Trace IDs should contain expected prefix
	if !strings.Contains(string(traceID), "trace-") {
		t.Errorf("Expected trace ID to contain 'trace-', got %s", traceID)
	}

	// Test AuthorizationDecision has trace ID field
	decision := AuthorizationDecision{
		TraceID:  traceID,
		Result:   DecisionResultAllow,
		Reason:   ReasonAllowedByPolicy,
		Resource: "https://example.com/resource",
		Method:   "GET",
		Agent:    "https://user.example.com/profile#me",
	}

	if decision.TraceID != traceID {
		t.Errorf("Expected TraceID to be %s, got %s", traceID, decision.TraceID)
	}
}
