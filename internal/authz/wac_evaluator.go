// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultWACEvaluatorOptions returns options with sensible defaults
func DefaultWACEvaluatorOptions() WACEvaluatorOptions {
	return WACEvaluatorOptions{
		MaxPolicies: 10,
		Timeout:     30 * time.Second,
		Logger:      nil,
	}
}

// WACEvaluator evaluates Web Access Control (WAC) policies in shadow mode
type WACEvaluator struct {
	options   WACEvaluatorOptions
	parser    *WACParser
	RDFParser *RDFParserRegistry
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
		options:   options,
		parser:    options.Parser,
		RDFParser: rdfParser,
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
// This is a placeholder that will be enhanced when integrated with actual policy loading
func (e *WACEvaluator) createPolicyFromDocument(ctx context.Context, doc PolicyDocument) (WACPolicy, error) {
	// For shadow mode, we return an empty policy
	// In a real implementation, we would:
	// 1. Fetch the policy content from doc.URI
	// 2. Parse it using the WAC parser
	// 3. Return the parsed policy

	// For now, create a default policy structure
	return WACPolicy{
		ResourceURI:      doc.URI,
		AuthorizationURI: doc.URI,
		Rules:            []WACRule{},
		Owner:            "",
	}, nil
}

// evaluateRequestAgainstPolicies evaluates a request against WAC policies
func (e *WACEvaluator) evaluateRequestAgainstPolicies(ctx context.Context, request Request, policies []WACPolicy) (DecisionValue, ReasonCode, int) {
	// In shadow mode, we always abstain for now
	// This will be enhanced to actually evaluate WAC rules

	// For demonstration purposes, we'll check if we have any policies
	if len(policies) == 0 {
		return DecisionAbstain, ReasonPolicyNotLoaded, 0
	}

	// Check if the request has an agent
	if request.AgentWebID == "" {
		// No agent, cannot make a decision
		return DecisionAbstain, ReasonPolicyNotLoaded, 0
	}

	// For now, abstain in shadow mode
	// Future: Actually evaluate WAC rules against the request
	return DecisionAbstain, ReasonKernelAbstainShadowMode, 0
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
