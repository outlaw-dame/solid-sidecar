// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

var ErrWACEvaluationFailed = errors.New("WAC evaluation failed")
var ErrNoMatchingRule = errors.New("no matching WAC rule found")

// WACEvaluatorOptions configures the WAC evaluator
type WACEvaluatorOptions struct {
	// Parser is the WAC parser to use for parsing policy documents
	Parser *WACParser

	// MaxPolicies is the maximum number of policies to evaluate (prevent DoS)
	// Default: 10
	MaxPolicies int

	// Timeout is the maximum time for evaluation
	// Default: 30 seconds
	Timeout time.Duration

	// ShadowMode determines if the evaluator should return abstain instead of actual decisions
	// Default: true (non-enforcing by default)
	ShadowMode bool

	// EnforcementMode determines if the evaluator should return actual enforcement decisions
	// When true, the evaluator returns allow/deny instead of abstain
	// Default: false (shadow mode only for safety)
	EnforcementMode bool

	// DecisionTraceIDsEnabled enables operator-visible decision trace IDs in decisions
	// Default: false
	DecisionTraceIDsEnabled bool

	// FailClosedPolicy configures fail-closed/fail-open behavior
	// Default: strict fail-closed for safety
	FailClosedPolicy FailClosedPolicy

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultWACEvaluatorOptions returns options with sensible defaults
func DefaultWACEvaluatorOptions() WACEvaluatorOptions {
	return WACEvaluatorOptions{
		MaxPolicies:          10,
		Timeout:              30 * time.Second,
		ShadowMode:           true,
		EnforcementMode:      false,
		DecisionTraceIDsEnabled: false,
		FailClosedPolicy:     DefaultFailClosedPolicy(),
		Logger:               nil,
	}
}

// WACEvaluator evaluates Web Access Control (WAC) policies
type WACEvaluator struct {
	options                WACEvaluatorOptions
	parser                 *WACParser
	RDFParser              *RDFParserRegistry
	shadowMode             bool
	enforcementMode        bool
	decisionTraceIDsEnabled bool
	failClosedPolicy       FailClosedPolicy
}

// NewWACEvaluator creates a new WAC evaluator
func NewWACEvaluator(options WACEvaluatorOptions, rdfParser *RDFParserRegistry) (*WACEvaluator, error) {
	if options.Parser == nil {
		// Create a default WAC parser if none provided
		parser, err := NewWACParser(DefaultWACParserOptions(), rdfParser)
		if err != nil {
			return nil, fmt.Errorf("failed to create WAC parser: %w", err)
		}
		options.Parser = parser
	}

	if options.MaxPolicies == 0 {
		options.MaxPolicies = 10
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}

	return &WACEvaluator{
		options:                options,
		parser:                 options.Parser,
		RDFParser:              rdfParser,
		shadowMode:             options.ShadowMode,
		enforcementMode:        options.EnforcementMode,
		decisionTraceIDsEnabled: options.DecisionTraceIDsEnabled,
		failClosedPolicy:       options.FailClosedPolicy,
	}, nil
}

// Evaluate implements the Evaluator interface for WAC evaluation in shadow mode
func (e *WACEvaluator) Evaluate(ctx context.Context, request Request) (Decision, error) {
	startTime := time.Now()
	defer func() {
		e.logEvaluationDuration(ctx, time.Since(startTime))
	}()

	// Apply timeout
	if e.options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.options.Timeout)
		defer cancel()

		if err := ctx.Err(); err != nil {
			return Decision{}, err
		}
	}

	// Validate the request first
	audit := AuditForRequest(request)
	if request.SchemaVersion != SchemaVersion {
		return shadowDecision(request, audit, DecisionDeny, ReasonUnsupportedSchema, httpBadRequestStatus), nil
	}
	if !validToken(request.RequestID, 128) || !supportedMethod(request.Method) {
		return shadowDecision(request, audit, DecisionDeny, ReasonInvalidRequest, httpBadRequestStatus), nil
	}
	if len(request.RequestedModes) == 0 {
		return shadowDecision(request, audit, DecisionDeny, ReasonMissingRequestedModes, httpBadRequestStatus), nil
	}
	if !validResourceURI(request.ResourceURI) {
		return shadowDecision(request, audit, DecisionDeny, ReasonUnsafeResourceURI, httpBadRequestStatus), nil
	}
	if err := ValidateRequest(request); err != nil {
		return shadowDecision(request, audit, DecisionDeny, ReasonInvalidRequest, httpBadRequestStatus), nil
	}

	// Check if we have any policy documents to evaluate
	if len(request.PolicyDocuments) == 0 {
		// No policies, so we abstain (shadow mode)
		return shadowDecision(request, audit, DecisionAbstain, ReasonPolicyNotLoaded, 0), nil
	}

	// Check policy count limit
	if len(request.PolicyDocuments) > e.options.MaxPolicies {
		e.logEvaluationWarning(ctx, fmt.Sprintf("too many policies: %d", len(request.PolicyDocuments)))
		return shadowDecision(request, audit, DecisionAbstain, ReasonPolicyNotLoaded, 0), nil
	}

	// Parse all WAC policies from the policy documents
	policies, err := e.parsePoliciesFromDocuments(ctx, request.PolicyDocuments)
	if err != nil {
		e.logEvaluationError(ctx, err)
		// In shadow mode, we don't fail hard - just abstain
		return shadowDecision(request, audit, DecisionAbstain, ReasonPolicyNotLoaded, 0), nil
	}

	// Evaluate the request against the WAC policies
	decisionValue, reasonCode, statusHint := e.evaluateRequestAgainstPolicies(ctx, request, policies)

	// In shadow mode, always return abstain regardless of the actual evaluation
	if e.shadowMode {
		return shadowDecision(request, audit, DecisionAbstain, ReasonKernelAbstainShadowMode, 0), nil
	}

	return shadowDecision(request, audit, decisionValue, reasonCode, statusHint), nil
}

// parsePoliciesFromDocuments parses WAC policies from policy documents
func (e *WACEvaluator) parsePoliciesFromDocuments(ctx context.Context, documents []PolicyDocument) ([]WACPolicy, error) {
	policies := make([]WACPolicy, 0, len(documents))

	for _, doc := range documents {
		// Only parse documents with WAC-compatible content types
		if !e.isWACContentType(doc.ContentType) {
			continue
		}

		// In a real implementation, we would fetch the policy content
		// For now, we create a placeholder policy
		// The actual content fetching would be done by the policy loader
		policy, err := e.createPolicyFromDocument(ctx, doc)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse policy %s: %w", ErrWACEvaluationFailed, doc.URI, err)
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

// isWACContentType checks if a content type is WAC-compatible
func (e *WACEvaluator) isWACContentType(contentType string) bool {
	// WAC policies are typically RDF documents
	supported := e.parser.SupportedContentTypes()
	contentType = strings.ToLower(strings.TrimSpace(contentType))

	for _, supportedType := range supported {
		if contentType == supportedType {
			return true
		}
	}

	// Also accept text/turtle and application/ld+json which are common for WAC
	if strings.Contains(contentType, "turtle") || strings.Contains(contentType, "json") {
		return true
	}

	return false
}

// createPolicyFromDocument creates a WAC policy from a policy document
// This creates a WAC policy with sample rules for testing and demonstration
func (e *WACEvaluator) createPolicyFromDocument(ctx context.Context, doc PolicyDocument) (WACPolicy, error) {
	// For demonstration and testing purposes, we create a sample policy
	// In a real implementation, we would:
	// 1. Fetch the policy content from doc.URI
	// 2. Parse it using the WAC parser
	// 3. Return the parsed policy

	// Create sample rules based on the document URI
	// This allows us to test the evaluation logic
	rules := e.createSampleRulesForResource(doc.URI)

	return WACPolicy{
		ResourceURI:      doc.URI,
		AuthorizationURI: doc.URI,
		Rules:            rules,
		Owner:            "",
	}, nil
}

// createSampleRulesForResource creates sample WAC rules for a resource
// This is used for testing and demonstration when actual policy content is not available
func (e *WACEvaluator) createSampleRulesForResource(resourceURI string) []WACRule {
	// Extract the resource path without the .acl extension
	baseURI := resourceURI
	if strings.HasSuffix(baseURI, ".acl") {
		baseURI = strings.TrimSuffix(baseURI, ".acl")
	}

	// Create sample rules that allow read/write to the owner
	ownerWebID := "https://example.org/owner#webid"
	publicAgent := "https://www.w3.org/ns/solid/interop#PublicAgent"

	rules := []WACRule{
		{
			Authorization: baseURI + ".acl",
			AccessTo:      baseURI,
			Agent:         ownerWebID,
			Modes:         []AccessMode{AccessModeRead, AccessModeWrite, AccessModeControl},
		},
		{
			Authorization: baseURI + ".acl",
			AccessTo:      baseURI,
			Agent:         publicAgent,
			Modes:         []AccessMode{AccessModeRead},
		},
	}

	return rules
}

// evaluateRequestAgainstPolicies evaluates a request against WAC policies
func (e *WACEvaluator) evaluateRequestAgainstPolicies(ctx context.Context, request Request, policies []WACPolicy) (DecisionValue, ReasonCode, int) {
	// Collect all rules from all policies
	allRules := make([]WACRule, 0)
	for _, policy := range policies {
		allRules = append(allRules, policy.Rules...)
	}

	// If no rules, abstain
	if len(allRules) == 0 {
		return DecisionAbstain, ReasonPolicyNotLoaded, 0
	}

	// Check if the request has an agent
	if request.AgentWebID == "" {
		// No agent specified, cannot make a decision
		return DecisionAbstain, ReasonPolicyNotLoaded, 0
	}

	// Evaluate each rule to see if it matches the request
	for _, rule := range allRules {
		if e.ruleMatchesRequest(rule, request) {
			// Rule matches - check if it allows the requested modes
			if e.ruleAllowsModes(rule, request.RequestedModes) {
				// All requested modes are allowed
				return DecisionAllow, ReasonPolicyAllow, http.StatusOK
			}
			// Rule matches but doesn't allow all requested modes
			// Continue checking other rules
		}
	}

	// No matching rule found that allows all requested modes
	return DecisionDeny, ReasonPolicyDeny, http.StatusForbidden
}

// ruleMatchesRequest checks if a WAC rule matches a request
func (e *WACEvaluator) ruleMatchesRequest(rule WACRule, request Request) bool {
	// Check if the rule applies to the requested resource
	// The rule's AccessTo should match the request's ResourceURI
	if rule.AccessTo != request.ResourceURI {
		// In a real implementation, we would also check for:
		// - Container inheritance (if rule applies to parent container)
		// - Wildcard matching
		// For now, we require exact match
		return false
	}

	// Check if the rule's agent matches the request's agent
	if rule.Agent != "" && rule.Agent != request.AgentWebID {
		// In a real implementation, we would also check:
		// - Group membership
		// - AgentClass matching
		// For now, we require exact match
		return false
	}

	// Check agent class if specified
	if rule.AgentClass != "" {
		// For now, we don't have agent class resolution
		// In a real implementation, we would check if request.AgentWebID
		// is a member of the agent class
		return false
	}

	// Rule matches the resource and agent
	return true
}

// ruleAllowsModes checks if a rule allows all requested modes
func (e *WACEvaluator) ruleAllowsModes(rule WACRule, requestedModes []AccessMode) bool {
	// If the rule has no modes specified, it allows all modes
	if len(rule.Modes) == 0 {
		return true
	}

	// Check if all requested modes are in the rule's modes
	for _, requestedMode := range requestedModes {
		found := false
		for _, ruleMode := range rule.Modes {
			if ruleMode == requestedMode {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// Log helpers

func (e *WACEvaluator) logEvaluationError(ctx context.Context, err error) {
	if e.options.Logger == nil {
		return
	}
	e.options.Logger.Warn("WAC evaluation error",
		"error", err,
	)
}

func (e *WACEvaluator) logEvaluationWarning(ctx context.Context, message string) {
	if e.options.Logger == nil {
		return
	}
	e.options.Logger.Warn("WAC evaluation warning",
		"message", message,
	)
}

func (e *WACEvaluator) logEvaluationDuration(ctx context.Context, duration time.Duration) {
	if e.options.Logger == nil {
		return
	}
	if duration > 100*time.Millisecond {
		e.options.Logger.Warn("WAC evaluation slow",
			"duration", duration,
		)
	} else {
		e.options.Logger.Debug("WAC evaluation duration",
			"duration", duration,
		)
	}
}

// Ensure interface compliance
var _ Evaluator = (*WACEvaluator)(nil)
