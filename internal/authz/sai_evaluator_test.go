// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// TestSAIEvaluatorEvaluate tests SAI evaluator evaluation
func TestSAIEvaluatorEvaluate(t *testing.T) {
	t.Run("shadow mode abstains", func(t *testing.T) {
		options := DefaultSAIEvaluatorOptions()
		options.ShadowMode = true
		evaluator := NewSAIEvaluator(options, nil)

		request := Request{
			SchemaVersion:  SchemaVersion,
			RequestID:      "test-request-1",
			Method:         "GET",
			ResourceURI:    "https://example.org/resource",
			AgentWebID:     "https://example.org/alice#me",
			RequestedModes: []AccessMode{AccessModeRead},
		}

		decision, err := evaluator.Evaluate(context.Background(), request)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Decision != DecisionAbstain {
			t.Errorf("expected shadow mode to abstain, got %v", decision.Decision)
		}
		if decision.ReasonCode != ReasonSAIShadowModeAbstain {
			t.Errorf("expected shadow mode reason, got %v", decision.ReasonCode)
		}
	})

	t.Run("invalid request", func(t *testing.T) {
		options := DefaultSAIEvaluatorOptions()
		options.ShadowMode = true
		evaluator := NewSAIEvaluator(options, nil)

		request := Request{
			SchemaVersion: "invalid",
			RequestID:     "test-request-1",
		}

		decision, err := evaluator.Evaluate(context.Background(), request)
		// For invalid requests, the evaluator returns a proper decision with deny, no error
		if err != nil {
			t.Fatalf("evaluation failed: %v", err)
		}
		// The evaluator should return a decision with deny for invalid schema
		if decision.Decision != DecisionDeny {
			t.Errorf("expected decision to be Deny, got %v", decision.Decision)
		}
		if decision.ReasonCode != ReasonUnsupportedSchema {
			t.Errorf("expected reason code %q, got %q", ReasonUnsupportedSchema, decision.ReasonCode)
		}
	})

	t.Run("no policy documents", func(t *testing.T) {
		options := DefaultSAIEvaluatorOptions()
		options.ShadowMode = true
		evaluator := NewSAIEvaluator(options, nil)

		request := Request{
			SchemaVersion:   SchemaVersion,
			RequestID:       "test-request-1",
			Method:          "GET",
			ResourceURI:     "https://example.org/resource",
			AgentWebID:      "https://example.org/alice#me",
			RequestedModes:  []AccessMode{AccessModeRead},
			PolicyDocuments: []PolicyDocument{},
		}

		decision, err := evaluator.Evaluate(context.Background(), request)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// In shadow mode, should abstain
		if decision.Decision != DecisionAbstain {
			t.Errorf("expected abstain in shadow mode, got %v", decision.Decision)
		}
	})
}

// TestSAIEvaluatorWithPolicies tests SAI evaluator with actual policies
func TestSAIEvaluatorWithPolicies(t *testing.T) {
	t.Run("allows access with matching policy", func(t *testing.T) {
		options := DefaultSAIEvaluatorOptions()
		options.ShadowMode = false
		evaluator := NewSAIEvaluator(options, nil)

		// Create a policy that allows read
		policyJSON := `{
			"policyURI": "https://example.org/policy.sai",
			"resourceURI": "https://example.org/resource",
			"rules": [
				{
					"ruleID": "rule-1",
					"premise": {
						"agent": "https://example.org/alice#me",
						"resource": "https://example.org/resource"
					},
					"conclusion": {
						"allows": true,
						"grantedModes": ["read", "write"]
					},
					"enabled": true
				}
			],
			"owner": "https://example.org/alice#me"
		}`

		// Compute SHA256 hash of the policy content
		hash := sha256.Sum256([]byte(policyJSON))
		sha256Hex := hex.EncodeToString(hash[:])

		request := Request{
			SchemaVersion:  SchemaVersion,
			RequestID:      "test-request-1",
			Method:         "GET",
			ResourceURI:    "https://example.org/resource",
			AgentWebID:     "https://example.org/alice#me",
			RequestedModes: []AccessMode{AccessModeRead},
			PolicyDocuments: []PolicyDocument{
				{
					URI:         "https://example.org/policy.sai",
					SHA256:      sha256Hex,
					ContentType: "application/sai+json",
					Content:     []byte(policyJSON),
				},
			},
		}

		decision, err := evaluator.Evaluate(context.Background(), request)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should allow because policy grants read
		if decision.Decision != DecisionAllow {
			t.Errorf("expected allow, got %v", decision.Decision)
		}
	})

	t.Run("denies access without matching policy", func(t *testing.T) {
		options := DefaultSAIEvaluatorOptions()
		options.ShadowMode = false
		evaluator := NewSAIEvaluator(options, nil)

		// Create a policy that doesn't match the agent
		policyJSON := `{
			"policyURI": "https://example.org/policy.sai",
			"resourceURI": "https://example.org/resource",
			"rules": [
				{
					"ruleID": "rule-1",
					"premise": {
						"agent": "https://example.org/bob#me",
						"resource": "https://example.org/resource"
					},
					"conclusion": {
						"allows": true,
						"grantedModes": ["read"]
					},
					"enabled": true
				}
			],
			"owner": "https://example.org/bob#me"
		}`

		// Compute SHA256 hash of the policy content
		hash := sha256.Sum256([]byte(policyJSON))
		sha256Hex := hex.EncodeToString(hash[:])

		request := Request{
			SchemaVersion:  SchemaVersion,
			RequestID:      "test-request-1",
			Method:         "GET",
			ResourceURI:    "https://example.org/resource",
			AgentWebID:     "https://example.org/alice#me",
			RequestedModes: []AccessMode{AccessModeRead},
			PolicyDocuments: []PolicyDocument{
				{
					URI:         "https://example.org/policy.sai",
					SHA256:      sha256Hex,
					ContentType: "application/sai+json",
					Content:     []byte(policyJSON),
				},
			},
		}

		decision, err := evaluator.Evaluate(context.Background(), request)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should deny because no policy grants access to alice
		if decision.Decision != DecisionDeny {
			t.Errorf("expected deny, got %v", decision.Decision)
		}
	})
}

// TestSAIEvaluatorOptions tests SAI evaluator options
func TestSAIEvaluatorOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		options := DefaultSAIEvaluatorOptions()
		if !options.ShadowMode {
			t.Error("expected ShadowMode to be true by default")
		}
		if options.MaxInferenceDepth != SAIInferenceLimit {
			t.Errorf("expected MaxInferenceDepth to be %d, got %d", SAIInferenceLimit, options.MaxInferenceDepth)
		}
		if options.MaxDelegationDepth != SAIMaxDelegationDepth {
			t.Errorf("expected MaxDelegationDepth to be %d, got %d", SAIMaxDelegationDepth, options.MaxDelegationDepth)
		}
		if !options.EnableDelegation {
			t.Error("expected EnableDelegation to be true by default")
		}
	})

	t.Run("shadow mode can be disabled", func(t *testing.T) {
		options := DefaultSAIEvaluatorOptions()
		options.ShadowMode = false
		evaluator := NewSAIEvaluator(options, nil)
		if evaluator.IsShadowMode() {
			t.Error("expected shadow mode to be disabled")
		}
	})

	t.Run("SetShadowMode", func(t *testing.T) {
		evaluator := NewSAIEvaluator(DefaultSAIEvaluatorOptions(), nil)
		if !evaluator.IsShadowMode() {
			t.Error("expected shadow mode to be enabled by default")
		}
		evaluator.SetShadowMode(false)
		if evaluator.IsShadowMode() {
			t.Error("expected shadow mode to be disabled after SetShadowMode(false)")
		}
		evaluator.SetShadowMode(true)
		if !evaluator.IsShadowMode() {
			t.Error("expected shadow mode to be enabled after SetShadowMode(true)")
		}
	})
}

// TestSAIEvaluatorErrorHandling tests error handling in SAI evaluator
func TestSAIEvaluatorErrorHandling(t *testing.T) {
	t.Run("context cancelled", func(t *testing.T) {
		options := DefaultSAIEvaluatorOptions()
		options.ShadowMode = false
		evaluator := NewSAIEvaluator(options, nil)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		request := Request{
			SchemaVersion:  SchemaVersion,
			RequestID:      "test-request-1",
			Method:         "GET",
			ResourceURI:    "https://example.org/resource",
			AgentWebID:     "https://example.org/alice#me",
			RequestedModes: []AccessMode{AccessModeRead},
		}

		_, err := evaluator.Evaluate(ctx, request)
		if err == nil {
			t.Error("expected error for cancelled context")
		}
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context") {
			t.Errorf("expected context error, got: %v", err)
		}
	})

	t.Run("invalid request validation", func(t *testing.T) {
		options := DefaultSAIEvaluatorOptions()
		options.ShadowMode = false
		evaluator := NewSAIEvaluator(options, nil)

		// Create an invalid request (empty RequestID)
		request := Request{
			SchemaVersion:  SchemaVersion,
			RequestID:      "",
			Method:         "GET",
			ResourceURI:    "https://example.org/resource",
			AgentWebID:     "https://example.org/alice#me",
			RequestedModes: []AccessMode{AccessModeRead},
		}

		decision, err := evaluator.Evaluate(context.Background(), request)
		// For invalid requests, the evaluator returns a proper decision with deny, no error
		if err != nil {
			t.Fatalf("evaluation failed: %v", err)
		}
		// The evaluator should return a decision with deny for invalid request ID
		if decision.Decision != DecisionDeny {
			t.Errorf("expected decision to be Deny, got %v", decision.Decision)
		}
		if decision.ReasonCode != ReasonInvalidRequest {
			t.Errorf("expected reason code %q, got %q", ReasonInvalidRequest, decision.ReasonCode)
		}
	})
}

// TestSAIEvaluatorSortPoliciesByPriority tests policy sorting
func TestSAIEvaluatorSortPoliciesByPriority(t *testing.T) {
	policies := []SAIPolicy{
		{
			PolicyURI: "https://example.org/policy-1.sai",
			Rules: []SAIRule{
				{
					RuleID: "rule-1",
					Premise: SAIPremise{
						Agent:    "https://example.org/alice#me",
						Resource: "https://example.org/resource",
					},
					Conclusion: SAIConclusion{
						Allows:       true,
						GrantedModes: []AccessMode{AccessModeRead},
						Priority:     5,
					},
					Enabled: true,
				},
			},
		},
		{
			PolicyURI: "https://example.org/policy-2.sai",
			Rules: []SAIRule{
				{
					RuleID: "rule-2",
					Premise: SAIPremise{
						Agent:    "https://example.org/alice#me",
						Resource: "https://example.org/resource",
					},
					Conclusion: SAIConclusion{
						Allows:       true,
						GrantedModes: []AccessMode{AccessModeRead},
						Priority:     10,
					},
					Enabled: true,
				},
			},
		},
		{
			PolicyURI: "https://example.org/policy-3.sai",
			Rules: []SAIRule{
				{
					RuleID: "rule-3",
					Premise: SAIPremise{
						Agent:    "https://example.org/alice#me",
						Resource: "https://example.org/resource",
					},
					Conclusion: SAIConclusion{
						Allows:       true,
						GrantedModes: []AccessMode{AccessModeRead},
						Priority:     1,
					},
					Enabled: true,
				},
			},
		},
	}

	sorted := SortSAIPoliciesByPriority(policies)
	if len(sorted) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(sorted))
	}
	// Highest priority first
	if sorted[0].PolicyURI != "https://example.org/policy-2.sai" {
		t.Errorf("expected highest priority policy first, got %s", sorted[0].PolicyURI)
	}
	if sorted[1].PolicyURI != "https://example.org/policy-1.sai" {
		t.Errorf("expected second highest priority policy, got %s", sorted[1].PolicyURI)
	}
	if sorted[2].PolicyURI != "https://example.org/policy-3.sai" {
		t.Errorf("expected lowest priority policy last, got %s", sorted[2].PolicyURI)
	}
}
