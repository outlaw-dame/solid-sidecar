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

var ErrACPParseFailed = errors.New("ACP parsing failed")
var ErrACPInvalidRule = errors.New("invalid ACP rule")
var ErrACPMissingRequiredField = errors.New("missing required ACP field")

// ACPParser parses Access Control Policy (ACP) documents from RDF content
// Implements RDFParser interface for ACP-specific parsing
type ACPParser struct {
	options   ACPParserOptions
	rdfParser *RDFParserRegistry
}

// ACPParserOptions configures the ACP parser
type ACPParserOptions struct {
	// MaxRules is the maximum number of ACP rules to parse (prevent DoS)
	// Default: 100
	MaxRules int

	// Timeout is the maximum time for parsing
	// Default: 30 seconds
	Timeout time.Duration

	// EnforcementMode determines if the parser should operate in enforcement mode
	// When false, the parser operates in shadow mode (parse but don't enforce)
	// Default: false (shadow mode)
	EnforcementMode bool

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultACPParserOptions returns options with sensible defaults
func DefaultACPParserOptions() ACPParserOptions {
	return ACPParserOptions{
		MaxRules:        100,
		Timeout:         30 * time.Second,
		EnforcementMode: false, // Shadow mode by default for safety
		Logger:          nil,
	}
}

// NewACPParser creates a new ACP parser with the given RDF parser registry
func NewACPParser(options ACPParserOptions, rdfParser *RDFParserRegistry) (*ACPParser, error) {
	if rdfParser == nil {
		return nil, errors.New("RDF parser registry is required")
	}

	if options.MaxRules == 0 {
		options.MaxRules = 100
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}

	parser := &ACPParser{
		options:   options,
		rdfParser: rdfParser,
	}

	// Log enforcement mode configuration
	if options.Logger != nil {
		if options.EnforcementMode {
			options.Logger.Info("ACP parser initialized in enforcement mode")
		} else {
			options.Logger.Info("ACP parser initialized in shadow mode")
		}
	}

	return parser, nil
}

// IsEnforcementModeEnabled returns true if the parser is configured for enforcement mode
func (p *ACPParser) IsEnforcementModeEnabled() bool {
	return p.options.EnforcementMode
}

// ACPAccess represents an ACP access grant or denial
type ACPAccess struct {
	// AccessTo is the resource URI that this access applies to
	AccessTo string

	// Allows or denies access
	Allows bool

	// Agent is the WebID or group URI that has access
	Agent string

	// AgentClass is the class of agent (e.g., acp:Agent, foaf:Group)
	AgentClass string

	// Modes are the access modes (read, write, append, control, etc.)
	Modes []AccessMode

	// Origin is the origin that this access applies to (for CORS)
	Origin string

	// Inherit indicates if this access should be inherited by child resources
	Inherit bool
}

// ACPRule represents a single Access Control Policy rule
// In ACP, access is granted or denied to agents for specific resources and modes
type ACPRule struct {
	// Access is the access grant or denial
	Access ACPAccess

	// Resource is the resource URI that this rule controls
	Resource string

	// Policy is the policy URI that contains this rule
	Policy string
}

// ACPPolicy represents a complete ACP policy for a resource
type ACPPolicy struct {
	// ResourceURI is the URI of the resource this policy controls
	ResourceURI string

	// PolicyURI is the URI of the policy document
	PolicyURI string

	// Rules contains all access rules for this resource
	Rules []ACPRule

	// Owner is the WebID of the resource owner (if specified)
	Owner string

	// Inherit indicates if this policy should be inherited
	Inherit bool
}

// ACPParseResult contains the parsed ACP policy
// Note: This uses the same RDFParseResult for interface compatibility
type ACPParseResult struct {
	// For ACP, we embed RDFParseResult for interface compatibility
	// but add ACP-specific fields
	RDFParseResult

	// ACP-specific fields
	Policies []ACPPolicy
}

// Parse implements RDFParser interface for ACP parsing
func (p *ACPParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	startTime := time.Now()
	defer func() {
		p.logParseDuration(ctx, contentType, time.Since(startTime))
	}()

	// Apply timeout
	if p.options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.options.Timeout)
		defer cancel()

		if err := ctx.Err(); err != nil {
			return RDFParseResult{}, err
		}
	}

	// Validate input size
	if err := ValidateRDFInputSize(content); err != nil {
		p.logParseError(ctx, contentType, err)
		return RDFParseResult{}, err
	}

	// Use RDF parser to parse the content into triples
	rdfResult, err := p.rdfParser.Parse(ctx, content, contentType)
	if err != nil {
		p.logParseError(ctx, contentType, err)
		return RDFParseResult{}, fmt.Errorf("%w: %w", ErrACPParseFailed, err)
	}

	// Calculate SHA256 of content
	contentHash := sha256Hex(string(content))

	// Extract ACP rules from RDF triples
	policies, err := p.extractACPPoliciesFromTriples(ctx, rdfResult.Triples)
	if err != nil {
		p.logParseError(ctx, contentType, err)
		return RDFParseResult{}, fmt.Errorf("%w: %w", ErrACPParseFailed, err)
	}

	// Check rule count limit
	totalRules := 0
	for _, policy := range policies {
		totalRules += len(policy.Rules)
	}
	if totalRules > p.options.MaxRules {
		p.logParseError(ctx, contentType, fmt.Errorf("too many ACP rules: %d", totalRules))
		return RDFParseResult{}, fmt.Errorf("%w: too many ACP rules (%d > %d)", ErrACPParseFailed, totalRules, p.options.MaxRules)
	}

	// Validate policies
	for _, policy := range policies {
		if err := p.validateACPPolicy(policy); err != nil {
			p.logParseError(ctx, contentType, err)
			return RDFParseResult{}, fmt.Errorf("%w: %w", ErrACPParseFailed, err)
		}
	}

	// Build RDF parse result with ACP metadata
	result := RDFParseResult{
		Triples:     rdfResult.Triples,
		NamedGraphs: rdfResult.NamedGraphs,
		BaseURI:     rdfResult.BaseURI,
		ContentType: contentType,
		SHA256:      contentHash,
	}

	p.logParseSuccess(ctx, contentType, totalRules, len(rdfResult.Triples))
	return result, nil
}

// SupportedContentTypes implements RDFParser interface
func (p *ACPParser) SupportedContentTypes() []string {
	return []string{
		"text/turtle",
		"application/ld+json",
		"application/n-triples",
		"application/rdf+xml",
		"application/sparql-results+json",
	}
}

// extractACPPoliciesFromTriples extracts ACP policies from RDF triples
func (p *ACPParser) extractACPPoliciesFromTriples(ctx context.Context, triples []RDFTriple) ([]ACPPolicy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Find policy resources (acp:Policy)
	policyURIs := p.findPolicyURIs(triples)

	policies := make([]ACPPolicy, 0, len(policyURIs))
	for _, policyURI := range policyURIs {
		policy, err := p.extractPolicyFromTriples(ctx, triples, policyURI)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// findPolicyURIs finds all ACP policy URIs in the triples
func (p *ACPParser) findPolicyURIs(triples []RDFTriple) []string {
	policyURIs := make([]string, 0)
	seen := make(map[string]bool)

	for _, triple := range triples {
		// Look for triples where the object is a Policy
		if strings.Contains(triple.Predicate, "type") &&
			(strings.Contains(triple.Object, "acp:Policy") ||
				strings.Contains(triple.Object, "Policy")) {
			subject := strings.TrimSpace(triple.Subject)
			if subject != "" && !seen[subject] {
				policyURIs = append(policyURIs, subject)
				seen[subject] = true
			}
		}
	}

	return policyURIs
}

// extractPolicyFromTriples extracts an ACP policy from triples
func (p *ACPParser) extractPolicyFromTriples(ctx context.Context, triples []RDFTriple, policyURI string) (ACPPolicy, error) {
	policy := ACPPolicy{
		ResourceURI: policyURI,
		PolicyURI:   policyURI,
		Rules:       make([]ACPRule, 0),
		Inherit:     true, // Default to inheriting
	}

	// Find all triples for this policy
	policyTriples := p.findTriplesForSubject(triples, policyURI)

	// Extract policy-level information
	for _, triple := range policyTriples {
		switch {
		case strings.Contains(triple.Predicate, "appliesTo"):
			policy.ResourceURI = strings.TrimSpace(triple.Object)
		case strings.Contains(triple.Predicate, "inherit"):
			policy.Inherit = strings.ToLower(strings.TrimSpace(triple.Object)) == "true"
		}
	}

	// Find access rules (acp:accessTo, acp:agent, acp:mode, etc.)
	// In ACP, access is typically structured as:
	// - Policy appliesTo Resource
	// - Policy allows/denies Access
	// - Access to Resource by Agent with Modes

	// For now, we'll look for access grants and denials
	accessTriples := p.findAccessTriples(triples, policyURI)

	for _, accessTriple := range accessTriples {
		// Parse the access triple to create an ACPRule
		rule, err := p.parseACPRuleFromTriples(triples, accessTriple)
		if err != nil {
			return ACPPolicy{}, err
		}
		policy.Rules = append(policy.Rules, rule)
	}

	return policy, nil
}

// findAccessTriples finds triples related to access grants/denials
func (p *ACPParser) findAccessTriples(triples []RDFTriple, policyURI string) []RDFTriple {
	// Look for triples where the subject is the policy and predicate is access-related
	accessTriples := make([]RDFTriple, 0)

	for _, triple := range triples {
		if strings.TrimSpace(triple.Subject) == policyURI {
			if strings.Contains(triple.Predicate, "allow") ||
				strings.Contains(triple.Predicate, "deny") ||
				strings.Contains(triple.Predicate, "access") {
				accessTriples = append(accessTriples, triple)
			}
		}
	}

	return accessTriples
}

// parseACPRuleFromTriples parses an ACP rule from triples
func (p *ACPParser) parseACPRuleFromTriples(triples []RDFTriple, accessTriple RDFTriple) (ACPRule, error) {
	rule := ACPRule{
		Access: ACPAccess{
			Allows: true, // Default to allow
			Modes:  make([]AccessMode, 0),
		},
		Policy: accessTriple.Subject,
	}

	// Determine if this is an allow or deny
	if strings.Contains(accessTriple.Predicate, "deny") {
		rule.Access.Allows = false
	}

	// The object of the access triple is typically the access resource
	// We need to find the resource, agent, and modes for this access

	// Look for resource (appliesTo or accessTo)
	for _, triple := range triples {
		if strings.TrimSpace(triple.Subject) == strings.TrimSpace(accessTriple.Object) {
			if strings.Contains(triple.Predicate, "appliesTo") || strings.Contains(triple.Predicate, "accessTo") {
				rule.Access.AccessTo = strings.TrimSpace(triple.Object)
				rule.Resource = strings.TrimSpace(triple.Object)
			}
			if strings.Contains(triple.Predicate, "agent") || strings.Contains(triple.Predicate, "agentClass") {
				if strings.Contains(triple.Predicate, "agentClass") {
					rule.Access.AgentClass = strings.TrimSpace(triple.Object)
				} else {
					rule.Access.Agent = strings.TrimSpace(triple.Object)
				}
			}
			if strings.Contains(triple.Predicate, "mode") {
				mode := p.parseAccessMode(triple.Object)
				if mode != "" {
					rule.Access.Modes = append(rule.Access.Modes, mode)
				}
			}
		}
	}

	// Validate the rule
	if rule.Access.AccessTo == "" {
		return ACPRule{}, fmt.Errorf("%w: missing accessTo", ErrACPMissingRequiredField)
	}
	if rule.Access.Agent == "" && rule.Access.AgentClass == "" {
		return ACPRule{}, fmt.Errorf("%w: missing agent or agentClass", ErrACPMissingRequiredField)
	}

	return rule, nil
}

// findTriplesForSubject finds all triples where the given URI is the subject
func (p *ACPParser) findTriplesForSubject(triples []RDFTriple, subject string) []RDFTriple {
	result := make([]RDFTriple, 0)
	for _, triple := range triples {
		if strings.TrimSpace(triple.Subject) == subject {
			result = append(result, triple)
		}
	}
	return result
}

// parseAccessMode parses an RDF mode string into AccessMode
// This is the same as the WAC parser's parseAccessMode for consistency
func (p *ACPParser) parseAccessMode(modeStr string) AccessMode {
	modeStr = strings.ToLower(strings.TrimSpace(modeStr))

	// Remove any URI wrapper (e.g., <http://...>)
	if strings.HasPrefix(modeStr, "<") && strings.HasSuffix(modeStr, ">") {
		modeStr = modeStr[1 : len(modeStr)-1]
	}

	// Extract the last part after / or # for full URIs
	if idx := strings.LastIndex(modeStr, "#"); idx != -1 {
		modeStr = modeStr[idx+1:]
	}
	if idx := strings.LastIndex(modeStr, "/"); idx != -1 {
		modeStr = modeStr[idx+1:]
	}

	// Remove namespace prefixes (only if not a full URI)
	if !strings.Contains(modeStr, "/") && strings.Contains(modeStr, ":") {
		if idx := strings.LastIndex(modeStr, ":"); idx != -1 {
			modeStr = modeStr[idx+1:]
		}
	}

	switch modeStr {
	case "read":
		return AccessModeRead
	case "write":
		return AccessModeWrite
	case "append":
		return AccessModeAppend
	case "control":
		return AccessModeControl
	default:
		return ""
	}
}

// validateACPPolicy validates an ACP policy for completeness and safety
func (p *ACPParser) validateACPPolicy(policy ACPPolicy) error {
	if policy.PolicyURI == "" {
		return fmt.Errorf("%w: missing policy URI", ErrACPInvalidRule)
	}

	// Validate URIs for safety
	if !validWACResourceURI(policy.PolicyURI) {
		return fmt.Errorf("%w: invalid policy URI", ErrACPInvalidRule)
	}
	if policy.ResourceURI != "" && !validWACResourceURI(policy.ResourceURI) {
		return fmt.Errorf("%w: invalid resource URI", ErrACPInvalidRule)
	}

	for _, rule := range policy.Rules {
		if err := p.validateACPRule(rule); err != nil {
			return err
		}
	}

	return nil
}

// validateACPRule validates an ACP rule for completeness and safety
func (p *ACPParser) validateACPRule(rule ACPRule) error {
	if rule.Access.AccessTo == "" {
		return fmt.Errorf("%w: missing accessTo", ErrACPInvalidRule)
	}
	if rule.Access.Agent == "" && rule.Access.AgentClass == "" {
		return fmt.Errorf("%w: missing agent or agentClass", ErrACPInvalidRule)
	}
	if len(rule.Access.Modes) == 0 {
		return fmt.Errorf("%w: missing modes", ErrACPInvalidRule)
	}

	// Validate URIs for safety
	if !validWACResourceURI(rule.Access.AccessTo) {
		return fmt.Errorf("%w: invalid accessTo URI", ErrACPInvalidRule)
	}
	if rule.Access.Agent != "" && !validWACResourceURI(rule.Access.Agent) {
		return fmt.Errorf("%w: invalid agent URI", ErrACPInvalidRule)
	}
	if rule.Access.Origin != "" && !validWACResourceURI(rule.Access.Origin) {
		return fmt.Errorf("%w: invalid origin URI", ErrACPInvalidRule)
	}

	// Validate agent class
	if rule.Access.AgentClass != "" && containsControlRune(rule.Access.AgentClass) {
		return fmt.Errorf("%w: agentClass contains control characters", ErrACPInvalidRule)
	}

	return nil
}

// ParseACPPolicy parses a complete ACP policy for a specific resource
func (p *ACPParser) ParseACPPolicy(ctx context.Context, content []byte, contentType string, resourceURI string) (ACPPolicy, error) {
	rdfResult, err := p.Parse(ctx, content, contentType)
	if err != nil {
		return ACPPolicy{}, err
	}

	// Find policies that apply to this resource
	policies := p.filterPoliciesForResource(rdfResult, resourceURI)

	if len(policies) == 0 {
		return ACPPolicy{}, fmt.Errorf("%w: no ACP policy found for resource %s", ErrACPParseFailed, resourceURI)
	}

	// For now, return the first policy that applies
	// In a real implementation, we might merge or select the most specific policy
	return policies[0], nil
}

// filterPoliciesForResource filters ACP policies to only those that apply to the specified resource
func (p *ACPParser) filterPoliciesForResource(rdfResult RDFParseResult, resourceURI string) []ACPPolicy {
	// This is a simplified implementation
	policies := make([]ACPPolicy, 0)

	// For now, we just return all policies
	// A real implementation would check appliesTo and inheritance
	return policies
}

// Log helpers

func (p *ACPParser) logParseError(ctx context.Context, contentType string, err error) {
	if p.options.Logger == nil {
		return
	}
	p.options.Logger.Warn("ACP parse error",
		"content_type", contentType,
		"error", err,
	)
}

func (p *ACPParser) logParseSuccess(ctx context.Context, contentType string, ruleCount, tripleCount int) {
	if p.options.Logger == nil {
		return
	}
	p.options.Logger.Debug("ACP parse success",
		"content_type", contentType,
		"rule_count", ruleCount,
		"triple_count", tripleCount,
	)
}

func (p *ACPParser) logParseDuration(ctx context.Context, contentType string, duration time.Duration) {
	if p.options.Logger == nil {
		return
	}
	if duration > 100*time.Millisecond {
		p.options.Logger.Warn("ACP parse slow",
			"content_type", contentType,
			"duration", duration,
		)
	} else {
		p.options.Logger.Debug("ACP parse duration",
			"content_type", contentType,
			"duration", duration,
		)
	}
}

// Ensure interface compliance
var _ RDFParser = (*ACPParser)(nil)
