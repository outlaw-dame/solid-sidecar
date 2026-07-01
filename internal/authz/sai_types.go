// Package authz provides authorization policy handling for Solid.
package authz

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// SAISemanticsFamily is the policy semantics family identifier for SAI
const SAISemanticsFamily = PolicySemanticsFamily("sai")

// SAIReasonCode constants for SAI-specific decisions
const (
	ReasonSAIAllow                = ReasonCode("saiAllow")
	ReasonSAIDeny                 = ReasonCode("saiDeny")
	ReasonSAIInferenceAllow       = ReasonCode("saiInferenceAllow")
	ReasonSAIInferenceDeny        = ReasonCode("saiInferenceDeny")
	ReasonSAIRuleConflict         = ReasonCode("saiRuleConflict")
	ReasonSAIInvalidPolicy        = ReasonCode("saiInvalidPolicy")
	ReasonSAIUnsupportedInference = ReasonCode("saiUnsupportedInference")
	ReasonSAIMaxInferenceDepth    = ReasonCode("saiMaxInferenceDepth")
	ReasonSAICircularDelegation   = ReasonCode("saiCircularDelegation")
	ReasonSAIDelegationLimit      = ReasonCode("saiDelegationLimit")
	ReasonSAIPremiseNotMet        = ReasonCode("saiPremiseNotMet")
	ReasonSAIShadowModeAbstain    = ReasonCode("saiShadowModeAbstain")
)

// SAIInferenceLimit is the maximum depth of SAI inference chains
const SAIInferenceLimit = 10

// SAIMaxDelegationDepth is the maximum depth of delegation chains
const SAIMaxDelegationDepth = 5

// SAIMaxRulesPerPolicy is the maximum number of rules per SAI policy
const SAIMaxRulesPerPolicy = 100

// SAIMaxPolicySize is the maximum size of an SAI policy document in bytes
const SAIMaxPolicySize = 65536 // 64 KiB

// SAIAccessModeAny is the SAI-specific "any" access mode
const SAIAccessModeAny AccessMode = "any"

// SAIPremise represents the conditions for an SAI rule
type SAIPremise struct {
	// Agent is the agent or agent class that the rule applies to
	Agent string

	// AgentClass is the agent class (if Agent is a class reference)
	AgentClass string

	// Resource is the resource or resource class that the rule applies to
	Resource string

	// ResourceClass is the resource class (if Resource is a class reference)
	ResourceClass string

	// Mode is the access mode required by the premise
	Mode AccessMode

	// Context contains additional context conditions (e.g., time, purpose)
	Context string

	// Inherited indicates if this premise should be inherited by containers
	Inherited bool
}

// IsValid checks if the premise has valid values
func (p SAIPremise) IsValid() bool {
	if p.Agent == "" && p.AgentClass == "" {
		return false
	}
	if p.Resource == "" && p.ResourceClass == "" {
		return false
	}
	if p.Mode != "" && p.Mode != AccessModeRead && p.Mode != AccessModeWrite && p.Mode != AccessModeAppend && p.Mode != AccessModeControl && p.Mode != SAIAccessModeAny {
		return false
	}
	return true
}

// MatchesAgent checks if the premise matches the given agent
func (p SAIPremise) MatchesAgent(agent string, agentClasses []string) bool {
	if p.Agent != "" {
		return p.Agent == agent
	}
	if p.AgentClass != "" {
		for _, cls := range agentClasses {
			if cls == p.AgentClass {
				return true
			}
		}
	}
	// If no agent or agentClass specified, matches all
	return p.Agent == "" && p.AgentClass == ""
}

// MatchesResource checks if the premise matches the given resource
func (p SAIPremise) MatchesResource(resource string, resourceClasses []string) bool {
	if p.Resource != "" {
		return p.Resource == resource
	}
	if p.ResourceClass != "" {
		for _, cls := range resourceClasses {
			if cls == p.ResourceClass {
				return true
			}
		}
	}
	// If no resource or resourceClass specified, matches all
	return p.Resource == "" && p.ResourceClass == ""
}

// MatchesMode checks if the premise matches the requested mode
func (p SAIPremise) MatchesMode(mode AccessMode) bool {
	if p.Mode == "" || p.Mode == SAIAccessModeAny {
		return true
	}
	return p.Mode == mode
}

// SAIConclusion represents the conclusion of an SAI rule
type SAIConclusion struct {
	// Allows indicates whether the rule allows or denies access
	Allows bool

	// GrantedModes is the list of modes granted by this conclusion
	GrantedModes []AccessMode

	// DelegationChain is the chain of delegation (if any)
	DelegationChain string

	// Priority is the priority of this conclusion for conflict resolution
	Priority int

	// Inherited indicates if this conclusion should be inherited
	Inherited bool
}

// IsValid checks if the conclusion has valid values
func (c SAIConclusion) IsValid() bool {
	// Must have at least one granted mode if Allows is true
	if c.Allows && len(c.GrantedModes) == 0 && c.DelegationChain == "" {
		return false
	}
	// Check all granted modes are valid
	for _, m := range c.GrantedModes {
		if m != AccessModeRead && m != AccessModeWrite && m != AccessModeAppend && m != AccessModeControl && m != SAIAccessModeAny {
			return false
		}
	}
	return true
}

// SAIRule represents a single SAI rule with premise and conclusion
type SAIRule struct {
	// RuleID is a unique identifier for this rule
	RuleID string

	// Premise is the condition that must be met
	Premise SAIPremise

	// Conclusion is the authorization decision
	Conclusion SAIConclusion

	// Enabled indicates if this rule is active
	Enabled bool
}

// IsValid checks if the rule is valid
func (r SAIRule) IsValid() bool {
	if r.RuleID == "" {
		return false
	}
	if !r.Premise.IsValid() {
		return false
	}
	if !r.Conclusion.IsValid() {
		return false
	}
	return true
}

// MatchesRequest checks if the rule matches the given agent, resource, and mode
func (r SAIRule) MatchesRequest(agent string, agentClasses []string, resource string, resourceClasses []string, mode AccessMode) bool {
	if !r.Enabled || !r.IsValid() {
		return false
	}
	return r.Premise.MatchesAgent(agent, agentClasses) &&
		r.Premise.MatchesResource(resource, resourceClasses) &&
		r.Premise.MatchesMode(mode)
}

// GetGrantedModes returns the modes granted by this rule for the request
func (r SAIRule) GetGrantedModes() []AccessMode {
	if r.Conclusion.Allows {
		return r.Conclusion.GrantedModes
	}
	return nil
}

// SAIPolicy represents a complete SAI policy document
type SAIPolicy struct {
	// PolicyURI is the URI of this policy document
	PolicyURI string

	// ResourceURI is the resource this policy applies to
	ResourceURI string

	// Rules is the list of SAI rules in this policy
	Rules []SAIRule

	// Inherit indicates if this policy should be inherited by containers
	Inherit bool

	// Owner is the owner of this policy
	Owner string

	// Version is the policy version
	Version string

	// Created is the creation timestamp (RFC3339)
	Created string

	// Updated is the last update timestamp (RFC3339)
	Updated string
}

// IsValid checks if the policy is valid
func (p SAIPolicy) IsValid() bool {
	if p.PolicyURI == "" {
		return false
	}
	if len(p.Rules) > SAIMaxRulesPerPolicy {
		return false
	}
	for _, rule := range p.Rules {
		if !rule.IsValid() {
			return false
		}
	}
	return true
}

// GetApplicableRules returns rules that apply to the given agent and resource
func (p SAIPolicy) GetApplicableRules(agent string, resource string, mode AccessMode) []SAIRule {
	var applicable []SAIRule
	for _, rule := range p.Rules {
		if rule.MatchesRequest(agent, nil, resource, nil, mode) {
			applicable = append(applicable, rule)
		}
	}
	return applicable
}

// GetGrantedModes returns all modes granted by applicable rules for the requested modes
func (p SAIPolicy) GetGrantedModes(agent string, resource string, requestedModes []AccessMode) []AccessMode {
	applicableRules := p.GetApplicableRules(agent, resource, SAIAccessModeAny)

	var grantedSet map[AccessMode]bool
	for _, rule := range applicableRules {
		if rule.Conclusion.Allows {
			for _, mode := range rule.Conclusion.GrantedModes {
				if grantedSet == nil {
					grantedSet = make(map[AccessMode]bool)
				}
				grantedSet[mode] = true
			}
		}
	}

	if grantedSet == nil {
		return nil
	}

	var granted []AccessMode
	for _, mode := range requestedModes {
		if grantedSet[mode] || grantedSet[SAIAccessModeAny] {
			granted = append(granted, mode)
		}
	}

	return granted
}

// String returns a string representation of SAIPolicy
func (p SAIPolicy) String() string {
	var b strings.Builder
	b.WriteString("SAIPolicy{")
	b.WriteString(fmt.Sprintf("PolicyURI: %q, ", p.PolicyURI))
	b.WriteString(fmt.Sprintf("ResourceURI: %q, ", p.ResourceURI))
	b.WriteString(fmt.Sprintf("Rules: %d, ", len(p.Rules)))
	b.WriteString(fmt.Sprintf("Inherit: %v, ", p.Inherit))
	b.WriteString(fmt.Sprintf("Owner: %q, ", p.Owner))
	b.WriteString("}")
	return b.String()
}

// RedactedString returns a privacy-safe string representation
func (p SAIPolicy) RedactedString() string {
	var b strings.Builder
	b.WriteString("SAIPolicy{")
	b.WriteString(fmt.Sprintf("PolicyURI: %s, ", redactURI(p.PolicyURI)))
	b.WriteString(fmt.Sprintf("ResourceURI: %s, ", redactURI(p.ResourceURI)))
	b.WriteString(fmt.Sprintf("Rules: %d, ", len(p.Rules)))
	b.WriteString(fmt.Sprintf("Inherit: %v, ", p.Inherit))
	b.WriteString(fmt.Sprintf("Owner: %s", redactURI(p.Owner)))
	b.WriteString("}")
	return b.String()
}

// SAIParseResult represents the result of parsing an SAI policy document
type SAIParseResult struct {
	// Policy is the parsed SAI policy
	Policy SAIPolicy

	// RawContent is the original policy content
	RawContent []byte

	// ContentType is the content type of the policy
	ContentType string

	// SHA256 is the hash of the policy content
	SHA256 string

	// Warnings contains any parsing warnings
	Warnings []string

	// Errors contains any parsing errors (non-fatal)
	Errors []string
}

// IsValid checks if the parse result is valid
func (r SAIParseResult) IsValid() bool {
	return r.Policy.IsValid()
}

// SAIEvaluatorOptions configures the SAI evaluator
type SAIEvaluatorOptions struct {
	// ShadowMode indicates if the evaluator should only observe (default: true)
	ShadowMode bool

	// MaxInferenceDepth is the maximum depth of inference chains (default: 10)
	MaxInferenceDepth int

	// MaxDelegationDepth is the maximum depth of delegation chains (default: 5)
	MaxDelegationDepth int

	// EnableDelegation indicates if delegation chains should be followed
	EnableDelegation bool

	// MaxInputSize is the maximum size of input to parse (default: 64 KiB)
	MaxInputSize int64

	// Timeout is the maximum time allowed for evaluation (default: 30s)
	Timeout time.Duration

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultSAIEvaluatorOptions returns safe default options
func DefaultSAIEvaluatorOptions() SAIEvaluatorOptions {
	return SAIEvaluatorOptions{
		ShadowMode:         true, // Shadow mode by default
		MaxInferenceDepth:  SAIInferenceLimit,
		MaxDelegationDepth: SAIMaxDelegationDepth,
		EnableDelegation:   true,
		MaxInputSize:       SAIMaxPolicySize,
		Timeout:            30 * time.Second,
		Logger:             nil,
	}
}

// redactURI redacts sensitive information from URIs for logging
func redactURI(uri string) string {
	if uri == "" {
		return ""
	}
	// Extract host for privacy
	if strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://") {
		uri = strings.TrimPrefix(uri, "https://")
		uri = strings.TrimPrefix(uri, "http://")
		if idx := strings.Index(uri, "/"); idx >= 0 {
			return uri[:idx] + "/..."
		}
		return uri
	}
	return "[REDACTED]"
}
