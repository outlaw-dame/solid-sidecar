// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// SAIEvaluator implements Evaluator interface for SAI policy evaluation
type SAIEvaluator struct {
	// options configures the evaluator
	options SAIEvaluatorOptions

	// parser is the SAI parser to use
	parser *SAIParser

	// shadowMode indicates if evaluation is non-enforcing
	shadowMode bool

	// enforcementMode indicates if the evaluator should return actual enforcement decisions
	enforcementMode bool

	// decisionTraceIDsEnabled indicates if decision trace IDs should be generated
	decisionTraceIDsEnabled bool

	// failClosedPolicy configures fail-closed/fail-open behavior
	failClosedPolicy FailClosedPolicy

	// logger is the logger to use
	logger *slog.Logger
}

// ErrSAIEvaluation is returned when SAI evaluation fails
var ErrSAIEvaluation = errors.New("SAI evaluation failed")

// ErrSAIInferenceLimit is returned when inference depth limit is exceeded
var ErrSAIInferenceLimit = errors.New("SAI inference depth limit exceeded")

// ErrSAIDelegationLimit is returned when delegation depth limit is exceeded
var ErrSAIDelegationLimit = errors.New("SAI delegation depth limit exceeded")

// ErrSAICircularDelegation is returned when circular delegation is detected
var ErrSAICircularDelegation = errors.New("SAI circular delegation detected")

// NewSAIEvaluator creates a new SAI evaluator
func NewSAIEvaluator(options SAIEvaluatorOptions, parser *SAIParser) *SAIEvaluator {
	if parser == nil {
		parser = NewSAIParser(DefaultSAIParserOptions())
	}

	return &SAIEvaluator{
		options:                options,
		parser:                 parser,
		shadowMode:             options.ShadowMode,
		enforcementMode:        options.EnforcementMode,
		decisionTraceIDsEnabled: options.DecisionTraceIDsEnabled,
		failClosedPolicy:       options.FailClosedPolicy,
		logger:                 options.Logger,
	}
}

// NewSAIEvaluatorWithOptions creates a new SAI evaluator with custom options
func NewSAIEvaluatorWithOptions(options SAIEvaluatorOptions) *SAIEvaluator {
	parser := NewSAIParser(SAIParserOptions{
		MaxInputSize: options.MaxInputSize,
		Timeout:      options.Timeout,
		StrictMode:   true,
		Logger:       options.Logger,
	})

	return &SAIEvaluator{
		options:                options,
		parser:                 parser,
		shadowMode:             options.ShadowMode,
		enforcementMode:        options.EnforcementMode,
		decisionTraceIDsEnabled: options.DecisionTraceIDsEnabled,
		failClosedPolicy:       options.FailClosedPolicy,
		logger:                 options.Logger,
	}
}

// Evaluate evaluates SAI policies for the given request
// Implements Evaluator interface
func (e *SAIEvaluator) Evaluate(ctx context.Context, request Request) (Decision, error) {
	// Check context deadline
	if err := ctx.Err(); err != nil {
		return Decision{}, fmt.Errorf("%w: %v", ErrSAIEvaluation, err)
	}

	audit := AuditForRequest(request)

	// Validate request using individual checks to provide proper shadow decisions
	// Check schema version
	if request.SchemaVersion != SchemaVersion {
		return shadowDecision(request, audit, DecisionDeny, ReasonUnsupportedSchema, httpBadRequestStatus), nil
	}

	// Check for valid request ID
	if !validToken(request.RequestID, 128) {
		return shadowDecision(request, audit, DecisionDeny, ReasonInvalidRequest, httpBadRequestStatus), nil
	}

	// Check method is supported
	if !supportedMethod(request.Method) {
		return shadowDecision(request, audit, DecisionDeny, ReasonInvalidRequest, httpBadRequestStatus), nil
	}

	// Check resource URI is valid
	if !validResourceURI(request.ResourceURI) {
		return shadowDecision(request, audit, DecisionDeny, ReasonUnsafeResourceURI, httpBadRequestStatus), nil
	}

	// Check requested modes
	if len(request.RequestedModes) == 0 {
		return shadowDecision(request, audit, DecisionDeny, ReasonMissingRequestedModes, httpBadRequestStatus), nil
	}

	// In shadow mode, always abstain (non-enforcing)
	if e.shadowMode {
		return shadowDecision(request, audit, DecisionAbstain, ReasonSAIShadowModeAbstain, 0), nil
	}

	// Parse and evaluate SAI policies
	return e.evaluateSAIPolicies(ctx, request, audit)
}

// evaluateSAIPolicies evaluates SAI policies for the request
func (e *SAIEvaluator) evaluateSAIPolicies(ctx context.Context, request Request, audit AuditFields) (Decision, error) {
	var grantedModes []AccessMode
	var denyReasons []string
	var warnings []string

	// Process each policy document
	for _, policyDoc := range request.PolicyDocuments {
		// Skip non-SAI policies
		if !isSAIPolicyDocument(policyDoc) {
			continue
		}

		// Parse the SAI policy (only if content is available)
		if len(policyDoc.Content) == 0 {
			warnings = append(warnings, fmt.Sprintf("skipping SAI policy %s: no content available", policyDoc.URI))
			continue
		}
		parseResult, err := e.parser.ParseSAIPolicyDirect(ctx, policyDoc.Content)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("failed to parse SAI policy from %s: %v", policyDoc.URI, err))
			continue
		}

		if !parseResult.IsValid() {
			warnings = append(warnings, fmt.Sprintf("invalid SAI policy from %s", policyDoc.URI))
			for _, errMsg := range parseResult.Errors {
				warnings = append(warnings, fmt.Sprintf("  error: %s", errMsg))
			}
			continue
		}

		// Evaluate the policy
		policyGranted := parseResult.Policy.GetGrantedModes(
			request.AgentWebID,
			request.ResourceURI,
			request.RequestedModes,
		)

		if len(policyGranted) > 0 {
			grantedModes = append(grantedModes, policyGranted...)
		} else {
			denyReasons = append(denyReasons, fmt.Sprintf("policy %s denied access", policyDoc.URI))
		}
	}

	// Check if all requested modes are granted
	if ModesMatch(grantedModes, request.RequestedModes) {
		return Decision{
			SchemaVersion:   SchemaVersion,
			RequestID:       request.RequestID,
			Decision:        DecisionAllow,
			ReasonCode:      ReasonSAIAllow,
			StatusHint:      0,
			CacheTTLSeconds: 0,
			PolicyVersion:   request.PolicyVersion,
			ResourceVersion: request.ResourceVersion,
			Audit:           audit,
		}, nil
	}

	// Access denied
	return Decision{
		SchemaVersion:   SchemaVersion,
		RequestID:       request.RequestID,
		Decision:        DecisionDeny,
		ReasonCode:      ReasonSAIDeny,
		StatusHint:      403,
		CacheTTLSeconds: 0,
		PolicyVersion:   request.PolicyVersion,
		ResourceVersion: request.ResourceVersion,
		Audit:           audit,
	}, nil
}

// isSAIPolicyDocument checks if a policy document is an SAI policy
func isSAIPolicyDocument(policyDoc PolicyDocument) bool {
	contentType := strings.ToLower(policyDoc.ContentType)
	return strings.Contains(contentType, "sai") ||
		strings.Contains(contentType, "application/json") ||
		strings.Contains(policyDoc.URI, ".sai") ||
		strings.Contains(policyDoc.URI, "sai")
}

// EvaluateWithInference evaluates SAI policies with inference support
func (e *SAIEvaluator) EvaluateWithInference(ctx context.Context, request Request, policies []SAIPolicy) (Decision, []string, error) {
	audit := AuditForRequest(request)

	// In shadow mode, always abstain
	if e.shadowMode {
		return Decision{
			SchemaVersion:   SchemaVersion,
			RequestID:       request.RequestID,
			Decision:        DecisionAbstain,
			ReasonCode:      ReasonSAIShadowModeAbstain,
			StatusHint:      0,
			CacheTTLSeconds: 0,
			PolicyVersion:   request.PolicyVersion,
			ResourceVersion: request.ResourceVersion,
			Audit:           audit,
		}, []string{"shadow mode: SAI evaluation abstains"}, nil
	}

	// Track delegation depth
	delegationDepth := 0
	visitedPolicies := make(map[string]bool)

	// Evaluate with inference
	grantedModes, reasons, err := e.evaluateWithInference(ctx, request, policies, delegationDepth, visitedPolicies)
	if err != nil {
		return Decision{}, reasons, err
	}

	// Check if all requested modes are granted
	if ModesMatch(grantedModes, request.RequestedModes) {
		return Decision{
			SchemaVersion:   SchemaVersion,
			RequestID:       request.RequestID,
			Decision:        DecisionAllow,
			ReasonCode:      ReasonSAIInferenceAllow,
			StatusHint:      0,
			CacheTTLSeconds: 0,
			PolicyVersion:   request.PolicyVersion,
			ResourceVersion: request.ResourceVersion,
			Audit:           audit,
		}, reasons, nil
	}

	// Access denied
	return Decision{
		SchemaVersion:   SchemaVersion,
		RequestID:       request.RequestID,
		Decision:        DecisionDeny,
		ReasonCode:      ReasonSAIInferenceDeny,
		StatusHint:      403,
		CacheTTLSeconds: 0,
		PolicyVersion:   request.PolicyVersion,
		ResourceVersion: request.ResourceVersion,
		Audit:           audit,
	}, reasons, nil
}

// evaluateWithInference evaluates SAI policies with inference support
func (e *SAIEvaluator) evaluateWithInference(
	ctx context.Context,
	request Request,
	policies []SAIPolicy,
	delegationDepth int,
	visitedPolicies map[string]bool,
) ([]AccessMode, []string, error) {
	var grantedModes []AccessMode
	var reasons []string

	// Check delegation depth limit
	if delegationDepth > e.options.MaxDelegationDepth {
		return nil, nil, ErrSAIDelegationLimit
	}

	// Process each policy
	for _, policy := range policies {
		// Check for circular delegation
		if visitedPolicies[policy.PolicyURI] {
			reasons = append(reasons, fmt.Sprintf("circular delegation detected at %s", policy.PolicyURI))
			continue
		}
		visitedPolicies[policy.PolicyURI] = true

		// Evaluate direct rules
		policyGranted := policy.GetGrantedModes(
			request.AgentWebID,
			request.ResourceURI,
			request.RequestedModes,
		)

		if len(policyGranted) > 0 {
			grantedModes = append(grantedModes, policyGranted...)
			reasons = append(reasons, fmt.Sprintf("policy %s granted modes: %v", policy.PolicyURI, policyGranted))
		} else {
			reasons = append(reasons, fmt.Sprintf("policy %s denied access", policy.PolicyURI))
		}

		// Handle delegation if enabled
		if e.options.EnableDelegation {
			delegatedModes, delegatedReasons, err := e.handleDelegation(ctx, request, policy, delegationDepth+1, visitedPolicies)
			if err != nil {
				if errors.Is(err, ErrSAIDelegationLimit) || errors.Is(err, ErrSAICircularDelegation) {
					reasons = append(reasons, err.Error())
					continue
				}
				return grantedModes, reasons, err
			}
			grantedModes = append(grantedModes, delegatedModes...)
			reasons = append(reasons, delegatedReasons...)
		}
	}

	// Remove duplicates from granted modes
	grantedModes = removeDuplicateModes(grantedModes)

	return grantedModes, reasons, nil
}

// handleDelegation handles delegation chains in SAI policies
func (e *SAIEvaluator) handleDelegation(
	ctx context.Context,
	request Request,
	policy SAIPolicy,
	delegationDepth int,
	visitedPolicies map[string]bool,
) ([]AccessMode, []string, error) {
	var grantedModes []AccessMode
	var reasons []string

	// Check delegation depth limit
	if delegationDepth > e.options.MaxDelegationDepth {
		return nil, nil, ErrSAIDelegationLimit
	}

	// Find delegation rules
	for _, rule := range policy.Rules {
		if !rule.Enabled || !rule.Conclusion.Allows {
			continue
		}

		if rule.Conclusion.DelegationChain != "" {
			// Resolve delegation chain
			delegatedModes, delegatedReasons, err := e.resolveDelegationChain(
				ctx,
				request,
				rule.Conclusion.DelegationChain,
				delegationDepth,
				visitedPolicies,
			)
			if err != nil {
				return nil, nil, err
			}
			grantedModes = append(grantedModes, delegatedModes...)
			reasons = append(reasons, delegatedReasons...)
		}
	}

	return grantedModes, reasons, nil
}

// resolveDelegationChain resolves a delegation chain and evaluates the delegated policies
func (e *SAIEvaluator) resolveDelegationChain(
	ctx context.Context,
	request Request,
	delegationChain string,
	delegationDepth int,
	visitedPolicies map[string]bool,
) ([]AccessMode, []string, error) {
	// For now, return empty as delegation resolution requires policy discovery
	// which is out of scope for the initial implementation
	// This is a placeholder for future delegation chain resolution
	e.logDelegationWarning(fmt.Sprintf("delegation chain %s not resolved: delegation resolution not yet implemented", delegationChain))
	return nil, []string{fmt.Sprintf("delegation chain %s not resolved", delegationChain)}, nil
}

// removeDuplicateModes removes duplicate access modes from a slice
func removeDuplicateModes(modes []AccessMode) []AccessMode {
	if len(modes) <= 1 {
		return modes
	}

	set := make(map[AccessMode]bool)
	var unique []AccessMode
	for _, m := range modes {
		if !set[m] {
			set[m] = true
			unique = append(unique, m)
		}
	}
	return unique
}

// GetGrantedModes returns the modes granted by SAI policies for a request
func (e *SAIEvaluator) GetGrantedModes(ctx context.Context, request Request, policies []SAIPolicy) ([]AccessMode, error) {
	_, _, err := e.EvaluateWithInference(ctx, request, policies)
	if err != nil {
		return nil, err
	}

	// Extract granted modes from the decision
	// This would need to be refactored based on actual evaluation
	// For now, return all requested modes if any policy grants them
	for _, policy := range policies {
		if policy.IsValid() {
			granted := policy.GetGrantedModes(
				request.AgentWebID,
				request.ResourceURI,
				request.RequestedModes,
			)
			if len(granted) > 0 {
				return granted, nil
			}
		}
	}

	return nil, nil
}

// SetShadowMode enables or disables shadow mode
func (e *SAIEvaluator) SetShadowMode(enabled bool) {
	e.shadowMode = enabled
}

// IsShadowMode returns whether shadow mode is enabled
func (e *SAIEvaluator) IsShadowMode() bool {
	return e.shadowMode
}

// logEvaluationWarning logs an evaluation warning
func (e *SAIEvaluator) logEvaluationWarning(message string) {
	if e.logger != nil {
		e.logger.Warn("SAI evaluator warning", "message", message)
	}
}

// logEvaluationError logs an evaluation error
func (e *SAIEvaluator) logEvaluationError(message string) {
	if e.logger != nil {
		e.logger.Error("SAI evaluator error", "message", message)
	}
}

// logDelegationWarning logs a delegation warning
func (e *SAIEvaluator) logDelegationWarning(message string) {
	if e.logger != nil {
		e.logger.Warn("SAI delegation warning", "message", message)
	}
}

// SortSAIPoliciesByPriority sorts SAI policies by priority (higher priority first)
func SortSAIPoliciesByPriority(policies []SAIPolicy) []SAIPolicy {
	sort.Slice(policies, func(i, j int) bool {
		// Get max priority from each policy
		maxPriorityI := getMaxPriority(policies[i])
		maxPriorityJ := getMaxPriority(policies[j])
		return maxPriorityI > maxPriorityJ
	})
	return policies
}

// getMaxPriority returns the maximum priority from a policy's rules
func getMaxPriority(policy SAIPolicy) int {
	maxPriority := 0
	for _, rule := range policy.Rules {
		if rule.Conclusion.Priority > maxPriority {
			maxPriority = rule.Conclusion.Priority
		}
	}
	return maxPriority
}
