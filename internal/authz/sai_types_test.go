// Package authz provides authorization policy handling for Solid.
package authz

import (
	"fmt"
	"strings"
	"testing"
)

// TestSAIPremiseValidation tests SAIPremise validation
func TestSAIPremiseValidation(t *testing.T) {
	testCases := []struct {
		name     string
		premise  SAIPremise
		expected bool
	}{
		{
			name: "valid premise with agent and resource",
			premise: SAIPremise{
				Agent:    "https://example.org/alice#me",
				Resource: "https://example.org/resource",
				Mode:     AccessModeRead,
			},
			expected: true,
		},
		{
			name: "valid premise with agentClass and resourceClass",
			premise: SAIPremise{
				AgentClass:    "https://example.org/Agents",
				ResourceClass: "https://example.org/Resources",
				Mode:          AccessModeWrite,
			},
			expected: true,
		},
		{
			name: "valid premise with any mode",
			premise: SAIPremise{
				Agent:    "https://example.org/alice#me",
				Resource: "https://example.org/resource",
				Mode:     SAIAccessModeAny,
			},
			expected: true,
		},
		{
			name: "invalid premise without agent or agentClass",
			premise: SAIPremise{
				Resource: "https://example.org/resource",
				Mode:     AccessModeRead,
			},
			expected: false,
		},
		{
			name: "invalid premise without resource or resourceClass",
			premise: SAIPremise{
				Agent: "https://example.org/alice#me",
				Mode:  AccessModeRead,
			},
			expected: false,
		},
		{
			name: "invalid premise with invalid mode",
			premise: SAIPremise{
				Agent:    "https://example.org/alice#me",
				Resource: "https://example.org/resource",
				Mode:     AccessMode("invalid"),
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.premise.IsValid()
			if result != tc.expected {
				t.Errorf("expected IsValid() = %v, got %v", tc.expected, result)
			}
		})
	}
}

// TestSAIPremiseMatching tests SAIPremise matching functions
func TestSAIPremiseMatching(t *testing.T) {
	t.Run("MatchesAgent with direct agent match", func(t *testing.T) {
		premise := SAIPremise{
			Agent:    "https://example.org/alice#me",
			Resource: "https://example.org/resource",
		}
		if !premise.MatchesAgent("https://example.org/alice#me", nil) {
			t.Error("expected MatchesAgent to return true for direct match")
		}
		if premise.MatchesAgent("https://example.org/bob#me", nil) {
			t.Error("expected MatchesAgent to return false for non-matching agent")
		}
	})

	t.Run("MatchesAgent with agent class", func(t *testing.T) {
		premise := SAIPremise{
			AgentClass: "https://example.org/Agents",
			Resource:   "https://example.org/resource",
		}
		if !premise.MatchesAgent("", []string{"https://example.org/Agents"}) {
			t.Error("expected MatchesAgent to return true for matching agent class")
		}
		if premise.MatchesAgent("", []string{"https://example.org/OtherAgents"}) {
			t.Error("expected MatchesAgent to return false for non-matching agent class")
		}
	})

	t.Run("MatchesResource with direct resource match", func(t *testing.T) {
		premise := SAIPremise{
			Agent:    "https://example.org/alice#me",
			Resource: "https://example.org/resource",
		}
		if !premise.MatchesResource("https://example.org/resource", nil) {
			t.Error("expected MatchesResource to return true for direct match")
		}
		if premise.MatchesResource("https://example.org/other", nil) {
			t.Error("expected MatchesResource to return false for non-matching resource")
		}
	})

	t.Run("MatchesResource with resource class", func(t *testing.T) {
		premise := SAIPremise{
			Agent:         "https://example.org/alice#me",
			ResourceClass: "https://example.org/Resources",
		}
		if !premise.MatchesResource("", []string{"https://example.org/Resources"}) {
			t.Error("expected MatchesResource to return true for matching resource class")
		}
		if premise.MatchesResource("", []string{"https://example.org/OtherResources"}) {
			t.Error("expected MatchesResource to return false for non-matching resource class")
		}
	})

	t.Run("MatchesMode", func(t *testing.T) {
		premise := SAIPremise{
			Agent:    "https://example.org/alice#me",
			Resource: "https://example.org/resource",
			Mode:     AccessModeRead,
		}
		if !premise.MatchesMode(AccessModeRead) {
			t.Error("expected MatchesMode to return true for matching mode")
		}
		if premise.MatchesMode(AccessModeWrite) {
			t.Error("expected MatchesMode to return false for non-matching mode")
		}
		// Note: SAIAccessModeAny only matches if the premise mode is empty or SAIAccessModeAny
		// This premise has Mode=AccessModeRead, so it won't match SAIAccessModeAny
	})

	t.Run("MatchesMode with empty mode", func(t *testing.T) {
		premise := SAIPremise{
			Agent:    "https://example.org/alice#me",
			Resource: "https://example.org/resource",
			Mode:     "", // Empty mode matches any
		}
		if !premise.MatchesMode(AccessModeRead) {
			t.Error("expected MatchesMode to return true for empty premise mode")
		}
		if !premise.MatchesMode(AccessModeWrite) {
			t.Error("expected MatchesMode to return true for empty premise mode")
		}
		if !premise.MatchesMode(SAIAccessModeAny) {
			t.Error("expected MatchesMode to return true for empty premise mode with any mode")
		}
	})
}

// TestSAIConclusionValidation tests SAIConclusion validation
func TestSAIConclusionValidation(t *testing.T) {
	testCases := []struct {
		name       string
		conclusion SAIConclusion
		expected   bool
	}{
		{
			name: "valid allowing conclusion with modes",
			conclusion: SAIConclusion{
				Allows:       true,
				GrantedModes: []AccessMode{AccessModeRead, AccessModeWrite},
			},
			expected: true,
		},
		{
			name: "valid allowing conclusion with delegation chain",
			conclusion: SAIConclusion{
				Allows:          true,
				DelegationChain: "https://example.org/delegation",
			},
			expected: true,
		},
		{
			name: "valid denying conclusion",
			conclusion: SAIConclusion{
				Allows: false,
			},
			expected: true,
		},
		{
			name: "invalid allowing conclusion without modes or delegation",
			conclusion: SAIConclusion{
				Allows: true,
			},
			expected: false,
		},
		{
			name: "invalid conclusion with invalid mode",
			conclusion: SAIConclusion{
				Allows:       true,
				GrantedModes: []AccessMode{AccessMode("invalid")},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.conclusion.IsValid()
			if result != tc.expected {
				t.Errorf("expected IsValid() = %v, got %v", tc.expected, result)
			}
		})
	}
}

// TestSAIRuleValidation tests SAIRule validation
func TestSAIRuleValidation(t *testing.T) {
	testCases := []struct {
		name     string
		rule     SAIRule
		expected bool
	}{
		{
			name: "valid enabled rule",
			rule: SAIRule{
				RuleID: "rule-1",
				Premise: SAIPremise{
					Agent:    "https://example.org/alice#me",
					Resource: "https://example.org/resource",
					Mode:     AccessModeRead,
				},
				Conclusion: SAIConclusion{
					Allows:       true,
					GrantedModes: []AccessMode{AccessModeRead},
				},
				Enabled: true,
			},
			expected: true,
		},
		{
			name: "invalid rule without RuleID",
			rule: SAIRule{
				Premise: SAIPremise{
					Agent:    "https://example.org/alice#me",
					Resource: "https://example.org/resource",
				},
				Conclusion: SAIConclusion{
					Allows:       true,
					GrantedModes: []AccessMode{AccessModeRead},
				},
				Enabled: true,
			},
			expected: false,
		},
		{
			name: "invalid rule with invalid premise",
			rule: SAIRule{
				RuleID: "rule-1",
				Premise: SAIPremise{
					Resource: "https://example.org/resource",
				},
				Conclusion: SAIConclusion{
					Allows:       true,
					GrantedModes: []AccessMode{AccessModeRead},
				},
				Enabled: true,
			},
			expected: false,
		},
		{
			name: "invalid rule with invalid conclusion",
			rule: SAIRule{
				RuleID: "rule-1",
				Premise: SAIPremise{
					Agent:    "https://example.org/alice#me",
					Resource: "https://example.org/resource",
				},
				Conclusion: SAIConclusion{
					Allows: true,
				},
				Enabled: true,
			},
			expected: false,
		},
		{
			name: "disabled rule is still valid",
			rule: SAIRule{
				RuleID: "rule-1",
				Premise: SAIPremise{
					Agent:    "https://example.org/alice#me",
					Resource: "https://example.org/resource",
				},
				Conclusion: SAIConclusion{
					Allows:       true,
					GrantedModes: []AccessMode{AccessModeRead},
				},
				Enabled: false,
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.rule.IsValid()
			if result != tc.expected {
				t.Errorf("expected IsValid() = %v, got %v", tc.expected, result)
			}
		})
	}
}

// TestSAIRuleMatching tests SAIRule matching
func TestSAIRuleMatching(t *testing.T) {
	t.Run("MatchesRequest with matching rule", func(t *testing.T) {
		rule := SAIRule{
			RuleID: "rule-1",
			Premise: SAIPremise{
				Agent:    "https://example.org/alice#me",
				Resource: "https://example.org/resource",
				Mode:     AccessModeRead,
			},
			Conclusion: SAIConclusion{
				Allows:       true,
				GrantedModes: []AccessMode{AccessModeRead},
			},
			Enabled: true,
		}
		if !rule.MatchesRequest("https://example.org/alice#me", nil, "https://example.org/resource", nil, AccessModeRead) {
			t.Error("expected MatchesRequest to return true for matching request")
		}
	})

	t.Run("MatchesRequest with non-matching agent", func(t *testing.T) {
		rule := SAIRule{
			RuleID: "rule-1",
			Premise: SAIPremise{
				Agent:    "https://example.org/alice#me",
				Resource: "https://example.org/resource",
				Mode:     AccessModeRead,
			},
			Conclusion: SAIConclusion{
				Allows:       true,
				GrantedModes: []AccessMode{AccessModeRead},
			},
			Enabled: true,
		}
		if rule.MatchesRequest("https://example.org/bob#me", nil, "https://example.org/resource", nil, AccessModeRead) {
			t.Error("expected MatchesRequest to return false for non-matching agent")
		}
	})

	t.Run("MatchesRequest with disabled rule", func(t *testing.T) {
		rule := SAIRule{
			RuleID: "rule-1",
			Premise: SAIPremise{
				Agent:    "https://example.org/alice#me",
				Resource: "https://example.org/resource",
				Mode:     AccessModeRead,
			},
			Conclusion: SAIConclusion{
				Allows:       true,
				GrantedModes: []AccessMode{AccessModeRead},
			},
			Enabled: false,
		}
		if rule.MatchesRequest("https://example.org/alice#me", nil, "https://example.org/resource", nil, AccessModeRead) {
			t.Error("expected MatchesRequest to return false for disabled rule")
		}
	})
}

// TestSAIPolicyValidation tests SAIPolicy validation
func TestSAIPolicyValidation(t *testing.T) {
	t.Run("valid policy with rules", func(t *testing.T) {
		policy := SAIPolicy{
			PolicyURI:   "https://example.org/policy.sai",
			ResourceURI: "https://example.org/resource",
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
					},
					Enabled: true,
				},
			},
			Inherit: true,
			Owner:   "https://example.org/alice#me",
		}
		if !policy.IsValid() {
			t.Error("expected valid policy to return true for IsValid()")
		}
	})

	t.Run("invalid policy without PolicyURI", func(t *testing.T) {
		policy := SAIPolicy{
			ResourceURI: "https://example.org/resource",
			Rules:       []SAIRule{},
		}
		if policy.IsValid() {
			t.Error("expected invalid policy (no PolicyURI) to return false for IsValid()")
		}
	})

	t.Run("invalid policy with too many rules", func(t *testing.T) {
		rules := make([]SAIRule, SAIMaxRulesPerPolicy+1)
		for i := range rules {
			rules[i] = SAIRule{
				RuleID: fmt.Sprintf("rule-%d", i),
				Premise: SAIPremise{
					Agent:    "https://example.org/alice#me",
					Resource: "https://example.org/resource",
				},
				Conclusion: SAIConclusion{
					Allows:       true,
					GrantedModes: []AccessMode{AccessModeRead},
				},
				Enabled: true,
			}
		}
		policy := SAIPolicy{
			PolicyURI:   "https://example.org/policy.sai",
			ResourceURI: "https://example.org/resource",
			Rules:       rules,
		}
		if policy.IsValid() {
			t.Error("expected invalid policy (too many rules) to return false for IsValid()")
		}
	})

	t.Run("invalid policy with invalid rule", func(t *testing.T) {
		policy := SAIPolicy{
			PolicyURI:   "https://example.org/policy.sai",
			ResourceURI: "https://example.org/resource",
			Rules: []SAIRule{
				{
					RuleID: "", // Invalid: no RuleID
					Premise: SAIPremise{
						Agent:    "https://example.org/alice#me",
						Resource: "https://example.org/resource",
					},
					Conclusion: SAIConclusion{
						Allows:       true,
						GrantedModes: []AccessMode{AccessModeRead},
					},
					Enabled: true,
				},
			},
		}
		if policy.IsValid() {
			t.Error("expected invalid policy (invalid rule) to return false for IsValid()")
		}
	})
}

// TestSAIPolicyGetApplicableRules tests SAIPolicy GetApplicableRules
func TestSAIPolicyGetApplicableRules(t *testing.T) {
	policy := SAIPolicy{
		PolicyURI:   "https://example.org/policy.sai",
		ResourceURI: "https://example.org/resource",
		Rules: []SAIRule{
			{
				RuleID: "rule-1",
				Premise: SAIPremise{
					Agent:    "https://example.org/alice#me",
					Resource: "https://example.org/resource",
					// Empty mode matches any
				},
				Conclusion: SAIConclusion{
					Allows:       true,
					GrantedModes: []AccessMode{AccessModeRead},
				},
				Enabled: true,
			},
			{
				RuleID: "rule-2",
				Premise: SAIPremise{
					Agent:    "https://example.org/bob#me",
					Resource: "https://example.org/resource",
				},
				Conclusion: SAIConclusion{
					Allows:       true,
					GrantedModes: []AccessMode{AccessModeWrite},
				},
				Enabled: true,
			},
			{
				RuleID: "rule-3",
				Premise: SAIPremise{
					Agent:    "https://example.org/charlie#me",
					Resource: "https://example.org/other",
				},
				Conclusion: SAIConclusion{
					Allows:       true,
					GrantedModes: []AccessMode{AccessModeRead},
				},
				Enabled: true,
			},
		},
	}

	// Empty mode in premise matches any mode, so rule-1 should match
	applicable := policy.GetApplicableRules("https://example.org/alice#me", "https://example.org/resource", SAIAccessModeAny)
	if len(applicable) != 1 {
		t.Errorf("expected 1 applicable rule, got %d", len(applicable))
		return
	}
	if applicable[0].RuleID != "rule-1" {
		t.Errorf("expected rule-1 to be applicable, got %s", applicable[0].RuleID)
	}
}

// TestSAIPolicyGetGrantedModes tests SAIPolicy GetGrantedModes
func TestSAIPolicyGetGrantedModes(t *testing.T) {
	policy := SAIPolicy{
		PolicyURI:   "https://example.org/policy.sai",
		ResourceURI: "https://example.org/resource",
		Rules: []SAIRule{
			{
				RuleID: "rule-1",
				Premise: SAIPremise{
					Agent:    "https://example.org/alice#me",
					Resource: "https://example.org/resource",
				},
				Conclusion: SAIConclusion{
					Allows:       true,
					GrantedModes: []AccessMode{AccessModeRead, AccessModeWrite}, // No SAIAccessModeAny here
				},
				Enabled: true,
			},
		},
	}

	granted := policy.GetGrantedModes(
		"https://example.org/alice#me",
		"https://example.org/resource",
		[]AccessMode{AccessModeRead, AccessModeWrite, AccessModeAppend},
	)

	// Should return read and write (which are granted), but not append (not granted)
	if len(granted) != 2 {
		t.Errorf("expected 2 granted modes (read, write), got %d: %v", len(granted), granted)
	}
}

// TestSAIPolicyStringMethods tests string representations
func TestSAIPolicyStringMethods(t *testing.T) {
	t.Run("String representation", func(t *testing.T) {
		policy := SAIPolicy{
			PolicyURI:   "https://example.org/policy.sai",
			ResourceURI: "https://example.org/resource",
			Rules:       []SAIRule{},
			Inherit:     true,
			Owner:       "https://example.org/alice#me",
		}
		str := policy.String()
		if !strings.Contains(str, "https://example.org/policy.sai") {
			t.Errorf("expected String() to contain PolicyURI")
		}
		if !strings.Contains(str, "Rules: 0") {
			t.Errorf("expected String() to contain rule count")
		}
	})

	t.Run("RedactedString representation", func(t *testing.T) {
		policy := SAIPolicy{
			PolicyURI:   "https://example.org/policy.sai",
			ResourceURI: "https://example.org/resource",
			Rules:       []SAIRule{},
			Inherit:     true,
			Owner:       "https://example.org/alice#me",
		}
		str := policy.RedactedString()
		if !strings.Contains(str, "example.org") {
			t.Errorf("expected RedactedString() to contain host")
		}
		if strings.Contains(str, "policy.sai") {
			t.Errorf("expected RedactedString() to redact full URI")
		}
	})
}

// TestSAISemanticsFamily tests SAI family constant
func TestSAISemanticsFamily(t *testing.T) {
	if SAISemanticsFamily != PolicySemanticsFamily("sai") {
		t.Errorf("expected SAISemanticsFamily to be 'sai', got %s", SAISemanticsFamily)
	}
}

// TestSAIConstants tests SAI constants
func TestSAIConstants(t *testing.T) {
	t.Run("inference limit", func(t *testing.T) {
		if SAIInferenceLimit != 10 {
			t.Errorf("expected SAIInferenceLimit to be 10, got %d", SAIInferenceLimit)
		}
	})

	t.Run("delegation depth", func(t *testing.T) {
		if SAIMaxDelegationDepth != 5 {
			t.Errorf("expected SAIMaxDelegationDepth to be 5, got %d", SAIMaxDelegationDepth)
		}
	})

	t.Run("max rules per policy", func(t *testing.T) {
		if SAIMaxRulesPerPolicy != 100 {
			t.Errorf("expected SAIMaxRulesPerPolicy to be 100, got %d", SAIMaxRulesPerPolicy)
		}
	})

	t.Run("max policy size", func(t *testing.T) {
		if SAIMaxPolicySize != 65536 {
			t.Errorf("expected SAIMaxPolicySize to be 65536, got %d", SAIMaxPolicySize)
		}
	})
}

// TestSAIAccessModeAny tests SAI-specific access mode
func TestSAIAccessModeAny(t *testing.T) {
	if SAIAccessModeAny != AccessMode("any") {
		t.Errorf("expected SAIAccessModeAny to be 'any', got %s", SAIAccessModeAny)
	}
}
