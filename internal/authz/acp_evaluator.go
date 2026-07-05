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

var ErrACPEvaluationFailed = errors.New("ACP evaluation failed")
var ErrNoMatchingACPRule = errors.New("no matching ACP rule found")

// ACPEvaluatorOptions configures the ACP evaluator
type ACPEvaluatorOptions struct {
	// Parser is the ACP parser to use for parsing policy documents
	Parser *ACPParser

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

// DefaultACPEvaluatorOptions returns options with sensible defaults
func DefaultACPEvaluatorOptions() ACPEvaluatorOptions {
	return ACPEvaluatorOptions{
		MaxPolicies:          10,
		Timeout:              30 * time.Second,
		ShadowMode:           true,
		EnforcementMode:      false,
		DecisionTraceIDsEnabled: false,
		FailClosedPolicy:     DefaultFailClosedPolicy(),
		Logger:               nil,
	}
}

// ACPEvaluator evaluates Access Control Policies (ACP)
type ACPEvaluator struct {
	options                ACPEvaluatorOptions
	parser                 *ACPParser
	RDFParser              *RDFParserRegistry
	shadowMode             bool
	enforcementMode        bool
	decisionTraceIDsEnabled bool
	failClosedPolicy       FailClosedPolicy
}

// NewACPEvaluator creates a new ACP evaluator
func NewACPEvaluator(options ACPEvaluatorOptions, rdfParser *RDFParserRegistry) (*ACPEvaluator, error) {
	if options.Parser == nil {
		// Create a default ACP parser if none provided
		parser, err := NewACPParser(DefaultACPParserOptions(), rdfParser)
		if err != nil {
			return nil, fmt.Errorf("failed to create ACP parser: %w", err)
		}
		options.Parser = parser
	}

	if options.MaxPolicies == 0 {
		options.MaxPolicies = 10
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}

	return &ACPEvaluator{
		options:                options,
		parser:                 options.Parser,
		RDFParser:              rdfParser,
		shadowMode:             options.ShadowMode,
		enforcementMode:        options.EnforcementMode,
		decisionTraceIDsEnabled: options.DecisionTraceIDsEnabled,
		failClosedPolicy:       options.FailClosedPolicy,
	}, nil
}

// Evaluate implements the Evaluator interface for ACP evaluation in shadow mode
func (e *ACPEvaluator) Evaluate(ctx context.Context, request Request) (Decision, error) {
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

	// Parse all ACP policies from the policy documents
	policies, err := e.parsePoliciesFromDocuments(ctx, request.PolicyDocuments)
	if err != nil {
		e.logEvaluationError(ctx, err)
		// In shadow mode, we don't fail hard - just abstain
		return shadowDecision(request, audit, DecisionAbstain, ReasonPolicyNotLoaded, 0), nil
	}

	// Evaluate the request against the ACP policies
	decisionValue, reasonCode, statusHint := e.evaluateRequestAgainstPolicies(ctx, request, policies)

	// In shadow mode, always return abstain regardless of the actual evaluation
	if e.shadowMode {
		return shadowDecision(request, audit, DecisionAbstain, ReasonKernelAbstainShadowMode, 0), nil
	}

	return shadowDecision(request, audit, decisionValue, reasonCode, statusHint), nil
}

// parsePoliciesFromDocuments parses ACP policies from policy documents
func (e *ACPEvaluator) parsePoliciesFromDocuments(ctx context.Context, documents []PolicyDocument) ([]ACPPolicy, error) {
	policies := make([]ACPPolicy, 0, len(documents))

	for _, doc := range documents {
		// Only parse documents with ACP-compatible content types
		if !e.isACPContentType(doc.ContentType) {
			continue
		}

		// In a real implementation, we would fetch the policy content
		// For now, we create a placeholder policy
		policy, err := e.createPolicyFromDocument(ctx, doc)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse policy %s: %w", ErrACPEvaluationFailed, doc.URI, err)
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

// isACPContentType checks if a content type is ACP-compatible
func (e *ACPEvaluator) isACPContentType(contentType string) bool {
	// ACP policies are typically RDF documents
	supported := e.parser.SupportedContentTypes()
	contentType = strings.ToLower(strings.TrimSpace(contentType))

	for _, supportedType := range supported {
		if contentType == supportedType {
			return true
		}
	}

	// Also accept text/turtle and application/ld+json which are common for ACP
	if strings.Contains(contentType, "turtle") || strings.Contains(contentType, "json") {
		return true
	}

	return false
}

// createPolicyFromDocument creates an ACP policy from a policy document
func (e *ACPEvaluator) createPolicyFromDocument(ctx context.Context, doc PolicyDocument) (ACPPolicy, error) {
	// For demonstration and testing purposes, we create a sample policy
	// In a real implementation, we would:
	// 1. Fetch the policy content from doc.URI
	// 2. Parse it using the ACP parser
	// 3. Return the parsed policy

	// Create sample rules based on the document URI
	rules := e.createSampleRulesForResource(doc.URI)

	return ACPPolicy{
		ResourceURI: doc.URI,
		PolicyURI:   doc.URI,
		Rules:       rules,
		Owner:       "",
		Inherit:     false,
	}, nil
}

// createSampleRulesForResource creates sample ACP rules for a resource
func (e *ACPEvaluator) createSampleRulesForResource(resourceURI string) []ACPRule {
	// Extract the resource path without the .acl extension
	baseURI := resourceURI
	if strings.HasSuffix(baseURI, ".acl") {
		baseURI = strings.TrimSuffix(baseURI, ".acl")
	}

	// Create sample rules that allow read/write to the owner
	ownerWebID := "https://example.org/owner#webid"
	publicAgent := "https://www.w3.org/ns/solid/interop#PublicAgent"

	rules := []ACPRule{
		{
			Access: ACPAccess{
				AccessTo: baseURI,
				Allows:   true,
				Agent:    ownerWebID,
				Modes:    []AccessMode{AccessModeRead, AccessModeWrite, AccessModeControl, AccessModeAppend},
			},
			Resource: baseURI,
			Policy:   baseURI + ".acl",
		},
		{
			Access: ACPAccess{
				AccessTo: baseURI,
				Allows:   true,
				Agent:    publicAgent,
				Modes:    []AccessMode{AccessModeRead},
			},
			Resource: baseURI,
			Policy:   baseURI + ".acl",
		},
	}

	return rules
}

// evaluateRequestAgainstPolicies evaluates a request against ACP policies
func (e *ACPEvaluator) evaluateRequestAgainstPolicies(ctx context.Context, request Request, policies []ACPPolicy) (DecisionValue, ReasonCode, int) {
	// Collect all rules from all policies
	allRules := make([]ACPRule, 0)
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

// ruleMatchesRequest checks if an ACP rule matches a request
func (e *ACPEvaluator) ruleMatchesRequest(rule ACPRule, request Request) bool {
	// Check if the rule applies to the requested resource
	// In ACP, the rule's Access.AccessTo field specifies which resource the rule applies to
	if rule.Access.AccessTo != request.ResourceURI {
		// In a real implementation, we would also check for:
		// - Container inheritance
		// - Wildcard matching
		// For now, we require exact match
		return false
	}

	// Check if the rule's agent matches the request's agent
	if rule.Access.Agent != "" && rule.Access.Agent != request.AgentWebID {
		// In a real implementation, we would also check:
		// - Group membership
		// - AgentClass matching
		return false
	}

	// Check agent class if specified
	if rule.Access.AgentClass != "" {
		// For now, we don't have agent class resolution
		return false
	}

	// Rule matches the resource and agent
	return true
}

// ruleAllowsModes checks if a rule allows all requested modes
func (e *ACPEvaluator) ruleAllowsModes(rule ACPRule, requestedModes []AccessMode) bool {
	// Check if the rule allows the requested modes
	// In ACP, a rule allows if Access.Allows is true and all requested modes are in Access.Modes
	if !rule.Access.Allows {
		return false
	}

	// If the rule has no modes specified, it allows all modes
	if len(rule.Access.Modes) == 0 {
		return true
	}

	// Check if all requested modes are in the rule's modes
	for _, requestedMode := range requestedModes {
		found := false
		for _, ruleMode := range rule.Access.Modes {
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

func (e *ACPEvaluator) logEvaluationError(ctx context.Context, err error) {
	if e.options.Logger == nil {
		return
	}
	e.options.Logger.Warn("ACP evaluation error",
		"error", err,
	)
}

func (e *ACPEvaluator) logEvaluationWarning(ctx context.Context, message string) {
	if e.options.Logger == nil {
		return
	}
	e.options.Logger.Warn("ACP evaluation warning",
		"message", message,
	)
}

func (e *ACPEvaluator) logEvaluationDuration(ctx context.Context, duration time.Duration) {
	if e.options.Logger == nil {
		return
	}
	if duration > 100*time.Millisecond {
		e.options.Logger.Warn("ACP evaluation slow",
			"duration", duration,
		)
	} else {
		e.options.Logger.Debug("ACP evaluation duration",
			"duration", duration,
		)
	}
}

// Ensure interface compliance
var _ Evaluator = (*ACPEvaluator)(nil)
