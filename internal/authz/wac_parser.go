// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

var ErrWACParseFailed = errors.New("WAC parsing failed")
var ErrWACInvalidRule = errors.New("invalid WAC rule")
var ErrWACMissingRequiredField = errors.New("missing required WAC field")

// WACParser parses Web Access Control (WAC) policies from RDF content
// Implements RDFParser interface for WAC-specific parsing
type WACParser struct {
	options   WACParserOptions
	rdfParser *RDFParserRegistry
}

// WACParserOptions configures the WAC parser
type WACParserOptions struct {
	// MaxRules is the maximum number of WAC rules to parse (prevent DoS)
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

// DefaultWACParserOptions returns options with sensible defaults
func DefaultWACParserOptions() WACParserOptions {
	return WACParserOptions{
		MaxRules:        100,
		Timeout:         30 * time.Second,
		EnforcementMode: false, // Shadow mode by default for safety
		Logger:          nil,
	}
}

// NewWACParser creates a new WAC parser with the given RDF parser registry
func NewWACParser(options WACParserOptions, rdfParser *RDFParserRegistry) (*WACParser, error) {
	if rdfParser == nil {
		return nil, errors.New("RDF parser registry is required")
	}

	if options.MaxRules == 0 {
		options.MaxRules = 100
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}

	parser := &WACParser{
		options:   options,
		rdfParser: rdfParser,
	}

	// Log enforcement mode configuration
	if options.Logger != nil {
		if options.EnforcementMode {
			options.Logger.Info("WAC parser initialized in enforcement mode")
		} else {
			options.Logger.Info("WAC parser initialized in shadow mode")
		}
	}

	return parser, nil
}

// IsEnforcementModeEnabled returns true if the parser is configured for enforcement mode
func (p *WACParser) IsEnforcementModeEnabled() bool {
	return p.options.EnforcementMode
}

// WACRule represents a single Web Access Control rule
type WACRule struct {
	// Authorization is the URI of the acl:Authorization resource
	Authorization string

	// AccessTo is the resource URI that this rule applies to
	AccessTo string

	// Agent is the WebID or group URI that has access
	Agent string

	// AgentClass is the class of agent (e.g., acl:Agent, foaf:Group)
	AgentClass string

	// Mode is the access mode (read, write, control, append)
	Modes []AccessMode

	// DefaultAccess is the default access for this rule
	DefaultAccess bool

	// Origin is the origin that this rule applies to (for CORS)
	Origin string
}

// WACParseResult contains the parsed WAC policy
type WACParseResult struct {
	// Rules contains all the WAC rules found in the policy
	Rules []WACRule

	// AuthorizationURI is the URI of the main authorization resource
	AuthorizationURI string

	// AgentURIs contains all agent URIs found in the policy
	AgentURIs []string

	// AccessToURIs contains all resource URIs that have access controls
	AccessToURIs []string

	// ContentType is the original content type
	ContentType string

	// SHA256 is the hash of the original content
	SHA256 string

	// ParseDuration is how long parsing took
	ParseDuration time.Duration
}

// WACPolicy represents a complete WAC policy for a resource
type WACPolicy struct {
	// ResourceURI is the URI of the resource this policy controls
	ResourceURI string

	// AuthorizationURI is the URI of the authorization resource
	AuthorizationURI string

	// Rules contains all access rules for this resource
	Rules []WACRule

	// Owner is the WebID of the resource owner (if specified)
	Owner string
}

// Parse implements RDFParser interface for WAC parsing
func (p *WACParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	startTime := time.Now()
	defer func() {
		p.logParseDuration(ctx, contentType, time.Since(startTime))
	}()

	// Apply timeout
	if p.options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.options.Timeout)
		defer cancel()
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
		return RDFParseResult{}, fmt.Errorf("%w: %w", ErrWACParseFailed, err)
	}

	// Calculate SHA256 of content
	contentHash := sha256Hex(string(content))

	// Extract WAC rules from RDF triples
	rules, err := p.extractWACRulesFromTriples(ctx, rdfResult.Triples)
	if err != nil {
		p.logParseError(ctx, contentType, err)
		return RDFParseResult{}, fmt.Errorf("%w: %w", ErrWACParseFailed, err)
	}

	// Check rule count limit
	if len(rules) > p.options.MaxRules {
		p.logParseError(ctx, contentType, fmt.Errorf("too many WAC rules: %d", len(rules)))
		return RDFParseResult{}, fmt.Errorf("%w: too many WAC rules (%d > %d)", ErrWACParseFailed, len(rules), p.options.MaxRules)
	}

	// Validate rules
	for _, rule := range rules {
		if err := p.validateWACRule(rule); err != nil {
			p.logParseError(ctx, contentType, err)
			return RDFParseResult{}, fmt.Errorf("%w: %w", ErrWACParseFailed, err)
		}
	}

	// Convert to RDF parse result
	triplesWithMetadata := make([]RDFTriple, 0, len(rdfResult.Triples))
	for _, triple := range rdfResult.Triples {
		// Add WAC-specific metadata if this is a WAC triple
		wacTriple := p.enhanceTripleWithWACMetadata(triple, rules)
		triplesWithMetadata = append(triplesWithMetadata, wacTriple)
	}

	result := RDFParseResult{
		Triples:     triplesWithMetadata,
		NamedGraphs: rdfResult.NamedGraphs,
		BaseURI:     rdfResult.BaseURI,
		ContentType: contentType,
		SHA256:      contentHash,
	}

	p.logParseSuccess(ctx, contentType, len(rules), len(rdfResult.Triples))
	return result, nil
}

// SupportedContentTypes implements RDFParser interface
func (p *WACParser) SupportedContentTypes() []string {
	return []string{
		"text/turtle",
		"application/ld+json",
		"application/n-triples",
		"application/rdf+xml",
		"application/sparql-results+json",
	}
}

// extractWACRulesFromTriples extracts WAC rules from RDF triples
func (p *WACParser) extractWACRulesFromTriples(ctx context.Context, triples []RDFTriple) ([]WACRule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Find authorization resources
	authorizationURIs := p.findAuthorizationURIs(triples)

	// Extract rules from each authorization
	rules := make([]WACRule, 0)
	for _, authURI := range authorizationURIs {
		authRules, err := p.extractRulesForAuthorization(ctx, triples, authURI)
		if err != nil {
			return nil, err
		}
		rules = append(rules, authRules...)
	}

	return rules, nil
}

// findAuthorizationURIs finds all acl:Authorization resources in the triples
func (p *WACParser) findAuthorizationURIs(triples []RDFTriple) []string {
	authURIs := make([]string, 0)
	seen := make(map[string]bool)

	for _, triple := range triples {
		// Look for triples where the object is an Authorization
		if strings.Contains(triple.Predicate, "type") &&
			(strings.Contains(triple.Object, "acl:Authorization") ||
				strings.Contains(triple.Object, "Authorization")) {
			subject := strings.TrimSpace(triple.Subject)
			if subject != "" && !seen[subject] {
				authURIs = append(authURIs, subject)
				seen[subject] = true
			}
		}
	}

	return authURIs
}

// extractRulesForAuthorization extracts WAC rules for a specific authorization resource
func (p *WACParser) extractRulesForAuthorization(ctx context.Context, triples []RDFTriple, authURI string) ([]WACRule, error) {
	rules := make([]WACRule, 0)

	// Find all triples related to this authorization
	authTriples := p.findTriplesForSubject(triples, authURI)

	// Extract rule information
	var rule WACRule
	rule.Authorization = authURI

	for _, triple := range authTriples {
		switch {
		case strings.Contains(triple.Predicate, "accessTo"):
			rule.AccessTo = strings.TrimSpace(triple.Object)
		case strings.Contains(triple.Predicate, "agent") || strings.Contains(triple.Predicate, "agentClass"):
			// This could be agent, agentClass, or agentGroup
			if strings.Contains(triple.Predicate, "agentClass") {
				rule.AgentClass = strings.TrimSpace(triple.Object)
			} else {
				rule.Agent = strings.TrimSpace(triple.Object)
			}
		case strings.Contains(triple.Predicate, "mode"):
			mode := p.parseAccessMode(triple.Object)
			if mode != "" {
				rule.Modes = append(rule.Modes, mode)
			}
		case strings.Contains(triple.Predicate, "default"):
			rule.DefaultAccess = strings.ToLower(strings.TrimSpace(triple.Object)) == "true"
		case strings.Contains(triple.Predicate, "origin"):
			rule.Origin = strings.TrimSpace(triple.Object)
		}
	}

	// Only add the rule if it has the essential fields
	if rule.AccessTo != "" && (rule.Agent != "" || rule.AgentClass != "") && len(rule.Modes) > 0 {
		rules = append(rules, rule)
	} else if rule.AccessTo == "" && rule.Agent == "" && rule.AgentClass == "" && len(rule.Modes) == 0 {
		// This might be just the authorization resource itself, not a rule
		// We can skip it
	} else {
		// Missing required fields
		return nil, fmt.Errorf("%w: incomplete WAC rule for authorization %s", ErrWACMissingRequiredField, authURI)
	}

	return rules, nil
}

// findTriplesForSubject finds all triples where the given URI is the subject
func (p *WACParser) findTriplesForSubject(triples []RDFTriple, subject string) []RDFTriple {
	result := make([]RDFTriple, 0)
	for _, triple := range triples {
		if strings.TrimSpace(triple.Subject) == subject {
			result = append(result, triple)
		}
	}
	return result
}

// parseAccessMode parses an RDF mode string into AccessMode
func (p *WACParser) parseAccessMode(modeStr string) AccessMode {
	modeStr = strings.ToLower(strings.TrimSpace(modeStr))

	// Remove any URI wrapper (e.g., <http://.../ns/auth/acl#Read>)
	if strings.HasPrefix(modeStr, "<") && strings.HasSuffix(modeStr, ">") {
		modeStr = modeStr[1 : len(modeStr)-1]
	}

	// Extract the last part after / or # for full URIs
	// (e.g., http://www.w3.org/ns/auth/acl#Read -> Read)
	if idx := strings.LastIndex(modeStr, "#"); idx != -1 {
		modeStr = modeStr[idx+1:]
	}
	if idx := strings.LastIndex(modeStr, "/"); idx != -1 {
		modeStr = modeStr[idx+1:]
	}

	// Remove namespace prefixes (e.g., acl:Read -> Read)
	// Only do this if there are no slashes left (not a full URI)
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

// validWACResourceURI validates a URI for WAC, allowing fragment identifiers (#)
// which are commonly used in WebID URIs (e.g., https://example.org/profile#me)
func validWACResourceURI(value string) bool {
	if value == "" || len(value) > 4096 {
		return false
	}
	// Allow fragments (#) but not backslashes
	if strings.Contains(value, "\\") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

// validateWACRule validates a WAC rule for completeness and safety
func (p *WACParser) validateWACRule(rule WACRule) error {
	if rule.Authorization == "" {
		return fmt.Errorf("%w: missing authorization", ErrWACInvalidRule)
	}
	if rule.AccessTo == "" {
		return fmt.Errorf("%w: missing accessTo", ErrWACInvalidRule)
	}
	if rule.Agent == "" && rule.AgentClass == "" {
		return fmt.Errorf("%w: missing agent or agentClass", ErrWACInvalidRule)
	}
	if len(rule.Modes) == 0 {
		return fmt.Errorf("%w: missing modes", ErrWACInvalidRule)
	}

	// Validate URIs for safety - use WAC-specific validation that allows fragments
	if !validWACResourceURI(rule.Authorization) {
		return fmt.Errorf("%w: invalid authorization URI", ErrWACInvalidRule)
	}
	if !validWACResourceURI(rule.AccessTo) {
		return fmt.Errorf("%w: invalid accessTo URI", ErrWACInvalidRule)
	}
	if rule.Agent != "" && !validWACResourceURI(rule.Agent) {
		return fmt.Errorf("%w: invalid agent URI", ErrWACInvalidRule)
	}
	if rule.Origin != "" && !validWACResourceURI(rule.Origin) {
		return fmt.Errorf("%w: invalid origin URI", ErrWACInvalidRule)
	}

	// Validate agent class
	if rule.AgentClass != "" && containsControlRune(rule.AgentClass) {
		return fmt.Errorf("%w: agentClass contains control characters", ErrWACInvalidRule)
	}

	return nil
}

// enhanceTripleWithWACMetadata adds WAC-specific metadata to triples
func (p *WACParser) enhanceTripleWithWACMetadata(triple RDFTriple, rules []WACRule) RDFTriple {
	// For now, just return the original triple
	// In future, we could add WAC-specific metadata
	return triple
}

// ParseWACPolicy parses a complete WAC policy for a specific resource
func (p *WACParser) ParseWACPolicy(ctx context.Context, content []byte, contentType string, resourceURI string) (WACPolicy, error) {
	rdfResult, err := p.Parse(ctx, content, contentType)
	if err != nil {
		return WACPolicy{}, err
	}

	// Find rules that apply to this resource
	rules := p.filterRulesForResource(rdfResult, resourceURI)

	// Find the authorization URI for this resource
	authURI := p.findAuthorizationForResource(rdfResult, resourceURI)

	// Find the owner
	owner := p.findOwner(rdfResult, resourceURI)

	return WACPolicy{
		ResourceURI:      resourceURI,
		AuthorizationURI: authURI,
		Rules:            rules,
		Owner:            owner,
	}, nil
}

// filterRulesForResource filters WAC rules to only those that apply to the specified resource
func (p *WACParser) filterRulesForResource(rdfResult RDFParseResult, resourceURI string) []WACRule {
	// This is a simplified implementation
	// In a real implementation, we would need to handle container inheritance, etc.
	rules := make([]WACRule, 0)

	// For now, return all rules that match the resource URI exactly
	// or are for a container that contains the resource
	for _, triple := range rdfResult.Triples {
		// Look for accessTo predicates
		if strings.Contains(triple.Predicate, "accessTo") {
			accessTo := strings.TrimSpace(triple.Object)
			if accessTo == resourceURI {
				// This rule applies to our resource
				// We would need to reconstruct the full rule here
				// For now, this is a placeholder
			}
		}
	}

	// For shadow mode, we return an empty list
	// This will be enhanced in future phases
	return rules
}

// findAuthorizationForResource finds the authorization resource for a given resource
func (p *WACParser) findAuthorizationForResource(rdfResult RDFParseResult, resourceURI string) string {
	// Look for authorization resources that control this resource
	for _, triple := range rdfResult.Triples {
		if strings.Contains(triple.Predicate, "accessTo") {
			if strings.TrimSpace(triple.Object) == resourceURI {
				return strings.TrimSpace(triple.Subject)
			}
		}
	}
	return ""
}

// findOwner finds the owner of a resource from WAC policy
func (p *WACParser) findOwner(rdfResult RDFParseResult, resourceURI string) string {
	// Look for owner information in the policy
	// This is a placeholder for actual owner detection
	return ""
}

// Log helpers

func (p *WACParser) logParseError(ctx context.Context, contentType string, err error) {
	if p.options.Logger == nil {
		return
	}
	p.options.Logger.Warn("WAC parse error",
		"content_type", contentType,
		"error", err,
	)
}

func (p *WACParser) logParseSuccess(ctx context.Context, contentType string, ruleCount, tripleCount int) {
	if p.options.Logger == nil {
		return
	}
	p.options.Logger.Debug("WAC parse success",
		"content_type", contentType,
		"rule_count", ruleCount,
		"triple_count", tripleCount,
	)
}

func (p *WACParser) logParseDuration(ctx context.Context, contentType string, duration time.Duration) {
	if p.options.Logger == nil {
		return
	}
	if duration > 100*time.Millisecond {
		p.options.Logger.Warn("WAC parse slow",
			"content_type", contentType,
			"duration", duration,
		)
	} else {
		p.options.Logger.Debug("WAC parse duration",
			"content_type", contentType,
			"duration", duration,
		)
	}
}

// Ensure interface compliance
var _ RDFParser = (*WACParser)(nil)
