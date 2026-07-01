// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// SAIParser implements RDFParser interface for SAI policy documents
type SAIParser struct {
	// options configures the parser
	options SAIParserOptions

	// rdfParser is the underlying RDF parser (optional)
	rdfParser *RDFParserRegistry

	// logger is the logger to use
	logger *slog.Logger
}

// SAIParserOptions configures SAI parser behavior
type SAIParserOptions struct {
	// MaxInputSize is the maximum size of input to parse (default: 64 KiB)
	MaxInputSize int64

	// Timeout is the maximum time allowed for parsing (default: 30s)
	Timeout time.Duration

	// StrictMode indicates if parsing should be strict (default: true)
	StrictMode bool

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultSAIParserOptions returns safe default options
func DefaultSAIParserOptions() SAIParserOptions {
	return SAIParserOptions{
		MaxInputSize: SAIMaxPolicySize,
		Timeout:      30 * time.Second,
		StrictMode:   true,
		Logger:       nil,
	}
}

// NewSAIParser creates a new SAI parser
func NewSAIParser(options SAIParserOptions) *SAIParser {
	if options.MaxInputSize <= 0 {
		options.MaxInputSize = SAIMaxPolicySize
	}
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Second
	}

	return &SAIParser{
		options:   options,
		rdfParser: nil, // Can be set later if RDF parsing is needed
		logger:    options.Logger,
	}
}

// NewSAIParserWithRDF creates a new SAI parser with RDF support
func NewSAIParserWithRDF(options SAIParserOptions, rdfParser *RDFParserRegistry) *SAIParser {
	parser := NewSAIParser(options)
	parser.rdfParser = rdfParser
	return parser
}

// Parse parses SAI policy content and returns structured policy information
// Implements RDFParser interface
func (p *SAIParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	// Check context deadline
	if err := ctx.Err(); err != nil {
		return RDFParseResult{}, fmt.Errorf("%w: %v", ErrRDFParseTimeout, err)
	}

	// Check content size
	if int64(len(content)) > p.options.MaxInputSize {
		return RDFParseResult{}, fmt.Errorf("%w: content size %d exceeds maximum %d", ErrRDFInputTooLarge, len(content), p.options.MaxInputSize)
	}

	// Validate content type
	if !p.isSupportedContentType(contentType) {
		return RDFParseResult{}, fmt.Errorf("%w: %s", ErrRDFContentTypeNotSupported, contentType)
	}

	// Parse the SAI policy
	saiPolicy, warnings, parseErr := p.parseSAIPolicy(content)
	if parseErr != nil {
		// JSON parsing errors are always fatal - we can't parse the structure at all
		// Non-strict mode only applies to validation errors, not parsing errors
		return RDFParseResult{}, fmt.Errorf("%w: %v", ErrRDFParseFailed, parseErr)
	}

	// Create RDF parse result
	return p.createRDFParseResultFromSAI(saiPolicy, content, contentType, warnings, nil), nil
}

// SupportedContentTypes returns the list of content types this parser supports
// Implements RDFParser interface
func (p *SAIParser) SupportedContentTypes() []string {
	return []string{
		"application/sai+json",
		"application/json",
		"text/sai",
	}
}

// isSupportedContentType checks if a content type is supported
func (p *SAIParser) isSupportedContentType(contentType string) bool {
	for _, supported := range p.SupportedContentTypes() {
		if strings.EqualFold(contentType, supported) {
			return true
		}
		// Also check without charset
		if strings.HasPrefix(contentType, supported+";") {
			return true
		}
	}
	return false
}

// parseSAIPolicy parses SAI policy content into SAIPolicy struct
func (p *SAIParser) parseSAIPolicy(content []byte) (SAIPolicy, []string, error) {
	var warnings []string
	var policy SAIPolicy

	// Try to parse as JSON
	if err := json.Unmarshal(content, &policy); err != nil {
		// Try to parse as JSON-LD or other formats if RDF parser is available
		if p.rdfParser != nil {
			return p.parseSAIFromRDF(content)
		}
		return SAIPolicy{}, nil, fmt.Errorf("failed to parse SAI policy: %w", err)
	}

	// Validate the policy
	if !policy.IsValid() {
		warnings = append(warnings, "policy validation warnings detected")
	}

	return policy, warnings, nil
}

// parseSAIFromRDF parses SAI policy from RDF format (if RDF parser is available)
func (p *SAIParser) parseSAIFromRDF(content []byte) (SAIPolicy, []string, error) {
	if p.rdfParser == nil {
		return SAIPolicy{}, nil, errors.New("RDF parser not available")
	}

	// This would parse RDF and convert to SAI policy structure
	// For now, return error as full RDF-to-SAI conversion is not implemented
	return SAIPolicy{}, nil, errors.New("RDF to SAI conversion not yet implemented")
}

// createRDFParseResultFromSAI creates an RDFParseResult from an SAI policy
func (p *SAIParser) createRDFParseResultFromSAI(policy SAIPolicy, content []byte, contentType string, warnings, errors []string) RDFParseResult {
	// Compute SHA256 hash
	hash := sha256.Sum256(content)

	// Convert SAI policy to RDF triples (simplified representation)
	triples := p.saiPolicyToTriples(policy)

	return RDFParseResult{
		Triples:     triples,
		NamedGraphs: nil,
		BaseURI:     policy.PolicyURI,
		ContentType: contentType,
		SHA256:      hex.EncodeToString(hash[:]),
	}
}

// saiPolicyToTriples converts SAI policy to RDF triples
func (p *SAIParser) saiPolicyToTriples(policy SAIPolicy) []RDFTriple {
	var triples []RDFTriple

	// Add policy metadata triples
	if policy.PolicyURI != "" {
		triples = append(triples, RDFTriple{
			Subject:    policy.PolicyURI,
			Predicate:  "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
			Object:     "https://solidproject.org/ns/sai#Policy",
			ObjectType: RDFTermTypeIRI,
		})
	}

	if policy.ResourceURI != "" {
		triples = append(triples, RDFTriple{
			Subject:    policy.PolicyURI,
			Predicate:  "https://solidproject.org/ns/sai#appliesTo",
			Object:     policy.ResourceURI,
			ObjectType: RDFTermTypeIRI,
		})
	}

	if policy.Owner != "" {
		triples = append(triples, RDFTriple{
			Subject:    policy.PolicyURI,
			Predicate:  "http://www.w3.org/ns/auth/acl#owner",
			Object:     policy.Owner,
			ObjectType: RDFTermTypeIRI,
		})
	}

	// Add rule triples
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		ruleURI := fmt.Sprintf("%s#rule-%s", policy.PolicyURI, rule.RuleID)

		// Rule type
		triples = append(triples, RDFTriple{
			Subject:    ruleURI,
			Predicate:  "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
			Object:     "https://solidproject.org/ns/sai#Rule",
			ObjectType: RDFTermTypeIRI,
		})

		// Rule ID
		triples = append(triples, RDFTriple{
			Subject:    ruleURI,
			Predicate:  "https://solidproject.org/ns/sai#ruleId",
			Object:     rule.RuleID,
			ObjectType: RDFTermTypeLiteral,
		})

		// Premise
		if rule.Premise.Agent != "" {
			triples = append(triples, RDFTriple{
				Subject:    ruleURI,
				Predicate:  "https://solidproject.org/ns/sai#agent",
				Object:     rule.Premise.Agent,
				ObjectType: RDFTermTypeIRI,
			})
		}
		if rule.Premise.AgentClass != "" {
			triples = append(triples, RDFTriple{
				Subject:    ruleURI,
				Predicate:  "https://solidproject.org/ns/sai#agentClass",
				Object:     rule.Premise.AgentClass,
				ObjectType: RDFTermTypeIRI,
			})
		}
		if rule.Premise.Resource != "" {
			triples = append(triples, RDFTriple{
				Subject:    ruleURI,
				Predicate:  "https://solidproject.org/ns/sai#resource",
				Object:     rule.Premise.Resource,
				ObjectType: RDFTermTypeIRI,
			})
		}
		if rule.Premise.ResourceClass != "" {
			triples = append(triples, RDFTriple{
				Subject:    ruleURI,
				Predicate:  "https://solidproject.org/ns/sai#resourceClass",
				Object:     rule.Premise.ResourceClass,
				ObjectType: RDFTermTypeIRI,
			})
		}
		if rule.Premise.Mode != "" {
			triples = append(triples, RDFTriple{
				Subject:    ruleURI,
				Predicate:  "https://solidproject.org/ns/sai#mode",
				Object:     string(rule.Premise.Mode),
				ObjectType: RDFTermTypeLiteral,
			})
		}

		// Conclusion
		triples = append(triples, RDFTriple{
			Subject:    ruleURI,
			Predicate:  "https://solidproject.org/ns/sai#allows",
			Object:     fmt.Sprintf("%v", rule.Conclusion.Allows),
			ObjectType: RDFTermTypeLiteral,
		})

		for _, mode := range rule.Conclusion.GrantedModes {
			triples = append(triples, RDFTriple{
				Subject:    ruleURI,
				Predicate:  "https://solidproject.org/ns/sai#grantsMode",
				Object:     string(mode),
				ObjectType: RDFTermTypeLiteral,
			})
		}

		if rule.Conclusion.Priority != 0 {
			triples = append(triples, RDFTriple{
				Subject:    ruleURI,
				Predicate:  "https://solidproject.org/ns/sai#priority",
				Object:     fmt.Sprintf("%d", rule.Conclusion.Priority),
				ObjectType: RDFTermTypeLiteral,
			})
		}
	}

	return triples
}

// ParseSAIPolicyDirect parses SAI policy content directly (without RDF conversion)
func (p *SAIParser) ParseSAIPolicyDirect(ctx context.Context, content []byte) (SAIParseResult, error) {
	// Check context deadline
	if err := ctx.Err(); err != nil {
		return SAIParseResult{}, fmt.Errorf("%w: %v", ErrRDFParseTimeout, err)
	}

	// Check content size
	if int64(len(content)) > p.options.MaxInputSize {
		return SAIParseResult{}, fmt.Errorf("%w: content size %d exceeds maximum %d", ErrRDFInputTooLarge, len(content), p.options.MaxInputSize)
	}

	// Compute SHA256 hash
	hash := sha256.Sum256(content)

	// Parse the SAI policy
	var policy SAIPolicy
	var warnings []string
	var errors []string

	if err := json.Unmarshal(content, &policy); err != nil {
		return SAIParseResult{}, fmt.Errorf("failed to parse SAI policy: %w", err)
	}

	// Validate
	if !policy.IsValid() {
		warnings = append(warnings, "policy validation warnings detected")
		for _, rule := range policy.Rules {
			if !rule.IsValid() {
				errors = append(errors, fmt.Sprintf("invalid rule: %s", rule.RuleID))
			}
		}
	}

	return SAIParseResult{
		Policy:      policy,
		RawContent:  content,
		ContentType: "application/sai+json",
		SHA256:      hex.EncodeToString(hash[:]),
		Warnings:    warnings,
		Errors:      errors,
	}, nil
}

// ParseSAIPolicyFromReader parses SAI policy from an io.Reader
func (p *SAIParser) ParseSAIPolicyFromReader(ctx context.Context, reader io.Reader, contentType string) (SAIParseResult, error) {
	// Read content with size limit
	limitedReader := io.LimitReader(reader, p.options.MaxInputSize+1)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return SAIParseResult{}, fmt.Errorf("failed to read SAI policy: %w", err)
	}

	// Check size
	if int64(len(content)) > p.options.MaxInputSize {
		return SAIParseResult{}, fmt.Errorf("%w: content size %d exceeds maximum %d", ErrRDFInputTooLarge, len(content), p.options.MaxInputSize)
	}

	return p.ParseSAIPolicyDirect(ctx, content)
}

// logParseWarning logs a parsing warning
func (p *SAIParser) logParseWarning(message string) {
	if p.logger != nil {
		p.logger.Warn("SAI parser warning", "message", message)
	}
}

// logParseError logs a parsing error
func (p *SAIParser) logParseError(message string) {
	if p.logger != nil {
		p.logger.Error("SAI parser error", "message", message)
	}
}
