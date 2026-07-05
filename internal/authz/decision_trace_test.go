package authz

import (
	"errors"
	"testing"
	"time"
)

func TestGenerateDecisionTraceID(t *testing.T) {
	t.Parallel()

	// Generate multiple trace IDs and ensure they're unique
	seen := make(map[DecisionTraceID]bool)
	for i := 0; i < 1000; i++ {
		id := GenerateDecisionTraceID()
		if seen[id] {
			t.Fatalf("duplicate trace ID generated: %s", id)
		}
		seen[id] = true

		// Ensure ID is not empty
		if id == "" {
			t.Fatal("generated empty trace ID")
		}

		// Ensure ID has prefix
		if len(id) < 6 || id[:5] != "trace" {
			t.Fatalf("trace ID has unexpected format: %s", id)
		}
	}
}

func TestNewAuthorizationDecision(t *testing.T) {
	t.Parallel()

	decision := NewAuthorizationDecision()

	// Check defaults
	if decision.TraceID == "" {
		t.Fatal("decision should have a trace ID")
	}
	if decision.Result != DecisionResultAbstain {
		t.Fatalf("expected default result to be abstain, got %s", decision.Result)
	}
	if decision.Reason != ReasonAbstainedNotImplemented {
		t.Fatalf("expected default reason to be abstained_not_implemented, got %s", decision.Reason)
	}
	if !decision.StrictMode {
		t.Fatal("expected strict mode to be true by default")
	}
	if decision.FallbackToCSS {
		t.Fatal("expected fallback to CSS to be false by default")
	}
	if decision.Timestamp.IsZero() {
		t.Fatal("expected timestamp to be set")
	}
}

func TestDecisionSetters(t *testing.T) {
	t.Parallel()

	decision := NewAuthorizationDecision()

	// Test Allow
	decision.Allow(ReasonAllowedByPolicy, "policy allows read access")
	if !decision.IsAllow() {
		t.Fatal("expected decision to be allow after Allow()")
	}
	if decision.Reason != ReasonAllowedByPolicy {
		t.Fatalf("expected reason to be %s, got %s", ReasonAllowedByPolicy, decision.Reason)
	}
	if decision.ReasonDetail != "policy allows read access" {
		t.Fatalf("expected detail to be 'policy allows read access', got %s", decision.ReasonDetail)
	}

	// Test Deny
	decision.Deny(ReasonDeniedByPolicy, "policy denies write access")
	if !decision.IsDeny() {
		t.Fatal("expected decision to be deny after Deny()")
	}
	if decision.Reason != ReasonDeniedByPolicy {
		t.Fatalf("expected reason to be %s, got %s", ReasonDeniedByPolicy, decision.Reason)
	}

	// Test Abstain
	decision.Abstain(ReasonAbstainedNoPolicy, "no policy found")
	if !decision.IsAbstain() {
		t.Fatal("expected decision to be abstain after Abstain()")
	}

	// Test Error
	decision.Error(ReasonErrorTimeout, "request timeout")
	if !decision.IsError() {
		t.Fatal("expected decision to be error after Error()")
	}

	// Test that only one result type is true at a time
	if decision.IsAllow() || decision.IsAbstain() {
		t.Fatal("expected only IsError() to be true after Error()")
	}
}

func TestDecisionResultCheckers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func(*AuthorizationDecision)
		check    func(*AuthorizationDecision) bool
		expected bool
	}{
		{
			name:     "IsAllow true",
			setup:    func(d *AuthorizationDecision) { d.Allow(ReasonAllowedByPolicy, "") },
			check:    func(d *AuthorizationDecision) bool { return d.IsAllow() },
			expected: true,
		},
		{
			name:     "IsDeny true",
			setup:    func(d *AuthorizationDecision) { d.Deny(ReasonDeniedByPolicy, "") },
			check:    func(d *AuthorizationDecision) bool { return d.IsDeny() },
			expected: true,
		},
		{
			name:     "IsAbstain true",
			setup:    func(d *AuthorizationDecision) { d.Abstain(ReasonAbstainedNoPolicy, "") },
			check:    func(d *AuthorizationDecision) bool { return d.IsAbstain() },
			expected: true,
		},
		{
			name:     "IsError true",
			setup:    func(d *AuthorizationDecision) { d.Error(ReasonErrorTimeout, "") },
			check:    func(d *AuthorizationDecision) bool { return d.IsError() },
			expected: true,
		},
		{
			name:     "IsAllow false when denied",
			setup:    func(d *AuthorizationDecision) { d.Deny(ReasonDeniedByPolicy, "") },
			check:    func(d *AuthorizationDecision) bool { return d.IsAllow() },
			expected: false,
		},
		{
			name:     "IsDeny false when allowed",
			setup:    func(d *AuthorizationDecision) { d.Allow(ReasonAllowedByPolicy, "") },
			check:    func(d *AuthorizationDecision) bool { return d.IsDeny() },
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := NewAuthorizationDecision()
			tt.setup(decision)
			result := tt.check(decision)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetReasonTaxonomy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		reason       DecisionReason
		category     string
		severity     string
		actionable   bool
		clientFacing bool
	}{
		// Allow reasons
		{ReasonAllowedByPolicy, "access_granted", "info", false, true},
		{ReasonAllowedByOwner, "access_granted", "info", false, true},
		{ReasonAllowedByPublicAccess, "access_granted", "info", false, true},
		{ReasonAllowedByACL, "access_granted", "info", false, true},
		{ReasonAllowedByACP, "access_granted", "info", false, true},
		{ReasonAllowedByWAC, "access_granted", "info", false, true},
		{ReasonAllowedBySAI, "access_granted", "info", false, true},

		// Deny reasons
		{ReasonDeniedByPolicy, "access_denied", "warning", true, true},
		{ReasonDeniedNoMatchingRule, "access_denied", "warning", true, true},
		{ReasonDeniedByOrigin, "access_denied", "warning", true, true},
		{ReasonDeniedByMethod, "access_denied", "warning", true, true},
		{ReasonDeniedByResourceType, "access_denied", "warning", true, true},
		{ReasonDeniedByAgent, "access_denied", "warning", true, true},
		{ReasonDeniedByACL, "access_denied", "warning", true, true},
		{ReasonDeniedByACP, "access_denied", "warning", true, true},
		{ReasonDeniedByWAC, "access_denied", "warning", true, true},
		{ReasonDeniedBySAI, "access_denied", "warning", true, true},

		// Abstain reasons
		{ReasonAbstainedParserError, "decision_abstained", "debug", true, false},
		{ReasonAbstainedNoPolicy, "decision_abstained", "debug", true, false},
		{ReasonAbstainedShadowMode, "decision_abstained", "debug", true, false},
		{ReasonAbstainedNotImplemented, "decision_abstained", "debug", true, false},

		// Error reasons
		{ReasonErrorInternal, "decision_error", "error", true, false},
		{ReasonErrorTimeout, "decision_error", "error", true, false},
		{ReasonErrorPolicyFetch, "decision_error", "error", true, false},
		{ReasonErrorValidation, "decision_error", "error", true, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			taxonomy := GetReasonTaxonomy(tt.reason)
			if taxonomy.Category != tt.category {
				t.Errorf("category: expected %q, got %q", tt.category, taxonomy.Category)
			}
			if taxonomy.Severity != tt.severity {
				t.Errorf("severity: expected %q, got %q", tt.severity, taxonomy.Severity)
			}
			if taxonomy.Actionable != tt.actionable {
				t.Errorf("actionable: expected %v, got %v", tt.actionable, taxonomy.Actionable)
			}
			if taxonomy.ClientFacing != tt.clientFacing {
				t.Errorf("clientFacing: expected %v, got %v", tt.clientFacing, taxonomy.ClientFacing)
			}
		})
	}
}

func TestDefaultFailClosedPolicy(t *testing.T) {
	t.Parallel()

	policy := DefaultFailClosedPolicy()

	if !policy.Enabled {
		t.Fatal("expected fail-closed policy to be enabled by default")
	}
	if !policy.DenyOnError {
		t.Fatal("expected DenyOnError to be true by default")
	}
	if !policy.DenyOnTimeout {
		t.Fatal("expected DenyOnTimeout to be true by default")
	}
	if !policy.DenyOnPolicyFetchError {
		t.Fatal("expected DenyOnPolicyFetchError to be true by default")
	}
	if !policy.DenyOnParserError {
		t.Fatal("expected DenyOnParserError to be true by default")
	}
}

func TestFailClosedPolicyShouldDeny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   FailClosedPolicy
		err      error
		expected bool
	}{
		{
			name:     "fail-closed enabled denies on error",
			policy:   FailClosedPolicy{Enabled: true, DenyOnError: true},
			err:      errors.New("some error"),
			expected: true,
		},
		{
			name:     "fail-closed disabled allows on error",
			policy:   FailClosedPolicy{Enabled: false, DenyOnError: true},
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "fail-closed enabled but DenyOnError false allows",
			policy:   FailClosedPolicy{Enabled: true, DenyOnError: false},
			err:      errors.New("some error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.ShouldDenyOnError(tt.err)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestFailClosedPolicyShouldDenyOnTimeout(t *testing.T) {
	t.Parallel()

	policy := DefaultFailClosedPolicy()

	if !policy.ShouldDenyOnTimeout() {
		t.Fatal("expected ShouldDenyOnTimeout to return true for default policy")
	}

	policy.Enabled = false
	if policy.ShouldDenyOnTimeout() {
		t.Fatal("expected ShouldDenyOnTimeout to return false when policy is disabled")
	}
}

func TestFailClosedPolicyShouldDenyOnPolicyFetchError(t *testing.T) {
	t.Parallel()

	policy := DefaultFailClosedPolicy()

	if !policy.ShouldDenyOnPolicyFetchError() {
		t.Fatal("expected ShouldDenyOnPolicyFetchError to return true for default policy")
	}

	policy.Enabled = false
	if policy.ShouldDenyOnPolicyFetchError() {
		t.Fatal("expected ShouldDenyOnPolicyFetchError to return false when policy is disabled")
	}
}

func TestFailClosedPolicyShouldDenyOnParserError(t *testing.T) {
	t.Parallel()

	policy := DefaultFailClosedPolicy()

	if !policy.ShouldDenyOnParserError() {
		t.Fatal("expected ShouldDenyOnParserError to return true for default policy")
	}

	policy.Enabled = false
	if policy.ShouldDenyOnParserError() {
		t.Fatal("expected ShouldDenyOnParserError to return false when policy is disabled")
	}
}

func TestAuthorizationDecisionIsSafeForAudit(t *testing.T) {
	t.Parallel()

	decision := NewAuthorizationDecision()

	if !decision.IsSafeForAudit() {
		t.Fatal("expected decision to be safe for audit")
	}

	decision.Allow(ReasonAllowedByPolicy, "test")
	if !decision.IsSafeForAudit() {
		t.Fatal("expected allow decision to be safe for audit")
	}

	decision.Deny(ReasonDeniedByPolicy, "test")
	if !decision.IsSafeForAudit() {
		t.Fatal("expected deny decision to be safe for audit")
	}

	decision.Error(ReasonErrorInternal, "test")
	if !decision.IsSafeForAudit() {
		t.Fatal("expected error decision to be safe for audit")
	}
}

func TestDecisionTimestamp(t *testing.T) {
	t.Parallel()

	before := time.Now()
	decision := NewAuthorizationDecision()
	after := time.Now()

	if decision.Timestamp.Before(before) || decision.Timestamp.After(after) {
		t.Fatal("timestamp should be between before and after")
	}
}
