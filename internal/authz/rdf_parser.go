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

var ErrRDFParseFailed = errors.New("RDF parsing failed")
var ErrRDFParserNotFound = errors.New("no RDF parser found for content type")
var ErrRDFContentTypeNotSupported = errors.New("RDF content type not supported")
var ErrRDFInputTooLarge = errors.New("RDF input too large")
var ErrRDFParseTimeout = errors.New("RDF parsing timed out")

// RDFParser is the interface for parsing RDF content into structured policy data
type RDFParser interface {
	// Parse parses RDF content and returns structured policy information
	Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error)

	// SupportedContentTypes returns the list of content types this parser supports
	SupportedContentTypes() []string
}

// RDFParseResult contains the parsed RDF data
type RDFParseResult struct {
	// Triples represents the parsed RDF triples (subject, predicate, object)
	Triples []RDFTriple

	// NamedGraphs represents named graphs if present
	NamedGraphs map[string][]RDFTriple

	// BaseURI is the base URI used for resolving relative URIs
	BaseURI string

	// ContentType is the original content type
	ContentType string

	// SHA256 is the hash of the original content
	SHA256 string
}

// RDFTriple represents a single RDF triple
type RDFTriple struct {
	Subject    string      `json:"subject"`
	Predicate  string      `json:"predicate"`
	Object     string      `json:"object"`
	ObjectType RDFTermType `json:"object_type"` // IRI, Literal, BlankNode
	Language   string      `json:"language,omitempty"`   // Language tag (for literals)
	Datatype   string      `json:"datatype,omitempty"`   // Datatype URI (for literals)
}

// RDFTermType represents the type of RDF term
type RDFTermType string

const (
	RDFTermTypeIRI       RDFTermType = "IRI"
	RDFTermTypeLiteral   RDFTermType = "Literal"
	RDFTermTypeBlankNode RDFTermType = "BlankNode"
)

// RDFParserOptions configures RDF parser behavior
type RDFParserOptions struct {
	// MaxInputSize is the maximum size of RDF input to parse (default: 1MB)
	MaxInputSize int64

	// Timeout is the maximum time allowed for parsing (default: 30s)
	Timeout time.Duration

	// AllowedContentTypes is the list of allowed content types
	// If empty, all supported types are allowed
	AllowedContentTypes []string

	// DisallowedContentTypes is the list of disallowed content types
	// These are always rejected even if AllowedContentTypes permits them
	DisallowedContentTypes []string

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultRDFParserOptions returns options with sensible defaults
func DefaultRDFParserOptions() RDFParserOptions {
	return RDFParserOptions{
		MaxInputSize: 1 << 20, // 1MB
		Timeout:      30 * time.Second,
		AllowedContentTypes: []string{
			"text/turtle",
			"application/ld+json",
			"application/n-triples",
			"application/rdf+xml",
			"application/sparql-results+json",
		},
		DisallowedContentTypes: []string{
			"text/html",
			"text/javascript",
			"application/javascript",
			"application/x-javascript",
			"application/ecmascript",
		},
		Logger: nil,
	}
}

// RDFParserRegistry manages multiple RDF parsers and selects the appropriate one
type RDFParserRegistry struct {
	options        RDFParserOptions
	parsers        []RDFParser
	contentTypeMap map[string]RDFParser
}

// NewRDFParserRegistry creates a new parser registry
func NewRDFParserRegistry(options RDFParserOptions) *RDFParserRegistry {
	registry := &RDFParserRegistry{
		options:        options,
		parsers:        make([]RDFParser, 0),
		contentTypeMap: make(map[string]RDFParser),
	}

	// Set defaults
	if options.MaxInputSize == 0 {
		options.MaxInputSize = 1 << 20
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}

	return registry
}

// Register adds a parser to the registry
func (r *RDFParserRegistry) Register(parser RDFParser) {
	r.parsers = append(r.parsers, parser)
	for _, contentType := range parser.SupportedContentTypes() {
		contentType = strings.ToLower(strings.TrimSpace(contentType))
		r.contentTypeMap[contentType] = parser
	}
}

// Parse selects the appropriate parser and parses the RDF content
func (r *RDFParserRegistry) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	// Apply context timeout if not already set
	if r.options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.options.Timeout)
		defer cancel()
	}

	// Check input size
	if int64(len(content)) > r.options.MaxInputSize {
		return RDFParseResult{}, fmt.Errorf("%w: input size %d exceeds limit %d", ErrRDFInputTooLarge, len(content), r.options.MaxInputSize)
	}

	// Normalize content type
	contentType = strings.ToLower(strings.TrimSpace(contentType))

	// Try to detect content type from content if not provided or generic
	if contentType == "" || contentType == "application/octet-stream" {
		detectedType := detectRDFContentType(content)
		if detectedType != "" {
			contentType = detectedType
		}
	}

	// Check if content type is allowed
	if r.isDisallowedContentType(contentType) {
		return RDFParseResult{}, fmt.Errorf("%w: %s", ErrRDFContentTypeNotSupported, contentType)
	}

	// Check if content type is explicitly allowed (if AllowedContentTypes is set)
	if len(r.options.AllowedContentTypes) > 0 && !r.isAllowedContentType(contentType) {
		return RDFParseResult{}, fmt.Errorf("%w: %s", ErrRDFContentTypeNotSupported, contentType)
	}

	// Find parser for this content type
	parser, ok := r.contentTypeMap[contentType]
	if !ok {
		return RDFParseResult{}, fmt.Errorf("%w: %s", ErrRDFParserNotFound, contentType)
	}

	// Parse with the selected parser
	result, err := parser.Parse(ctx, content, contentType)
	if err != nil {
		return RDFParseResult{}, fmt.Errorf("%w: %w", ErrRDFParseFailed, err)
	}

	// Validate the result
	if err := r.validateParseResult(result); err != nil {
		return RDFParseResult{}, fmt.Errorf("%w: %w", ErrRDFParseFailed, err)
	}

	return result, nil
}

// isAllowedContentType checks if a content type is in the allowed list
func (r *RDFParserRegistry) isAllowedContentType(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	for _, allowed := range r.options.AllowedContentTypes {
		if strings.ToLower(strings.TrimSpace(allowed)) == contentType {
			return true
		}
	}
	return false
}

// isDisallowedContentType checks if a content type is in the disallowed list
func (r *RDFParserRegistry) isDisallowedContentType(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	for _, disallowed := range r.options.DisallowedContentTypes {
		if strings.ToLower(strings.TrimSpace(disallowed)) == contentType {
			return true
		}
	}
	return false
}

// validateParseResult validates the parse result
func (r *RDFParserRegistry) validateParseResult(result RDFParseResult) error {
	// Check for control characters in any of the triples
	for _, triple := range result.Triples {
		if containsControlRune(triple.Subject) || containsControlRune(triple.Predicate) || containsControlRune(triple.Object) {
			return errors.New("RDF triple contains control characters")
		}
		if triple.Subject == "" || triple.Predicate == "" || triple.Object == "" {
			return errors.New("RDF triple has empty components")
		}
	}

	// Check named graphs
	for graphURI, triples := range result.NamedGraphs {
		if containsControlRune(graphURI) {
			return errors.New("named graph URI contains control characters")
		}
		for _, triple := range triples {
			if containsControlRune(triple.Subject) || containsControlRune(triple.Predicate) || containsControlRune(triple.Object) {
				return errors.New("named graph triple contains control characters")
			}
		}
	}

	return nil
}

// detectRDFContentType attempts to detect RDF content type from the content
func detectRDFContentType(content []byte) string {
	if len(content) == 0 {
		return ""
	}

	contentStr := string(content)

	// JSON-LD
	if strings.Contains(contentStr, "@context") && (strings.Contains(contentStr, "{") || strings.Contains(contentStr, "}")) {
		return "application/ld+json"
	}

	// Turtle
	if strings.Contains(contentStr, "@prefix") || strings.Contains(contentStr, "@base") {
		return "text/turtle"
	}

	// RDF/XML
	if strings.Contains(contentStr, "<rdf:RDF") {
		return "application/rdf+xml"
	}

	// N-Triples
	if strings.Contains(contentStr, "<") && strings.Contains(contentStr, ">") && strings.Contains(contentStr, " .") {
		return "application/n-triples"
	}

	return ""
}

// Log helpers

func (r *RDFParserRegistry) logParseError(ctx context.Context, contentType string, err error) {
	if r.options.Logger == nil {
		return
	}
	r.options.Logger.Warn("RDF parse error",
		"content_type", contentType,
		"error", err,
	)
}

func (r *RDFParserRegistry) logParseSuccess(ctx context.Context, contentType string, tripleCount int) {
	if r.options.Logger == nil {
		return
	}
	r.options.Logger.Debug("RDF parse success",
		"content_type", contentType,
		"triple_count", tripleCount,
	)
}

// maxRDFInputSize is the absolute maximum RDF input size to prevent DoS
const maxRDFInputSize = 10 << 20 // 10MB

// ValidateRDFInputSize checks if RDF input size is within safe limits
func ValidateRDFInputSize(content []byte) error {
	if len(content) > maxRDFInputSize {
		return fmt.Errorf("%w: input size %d exceeds absolute limit %d", ErrRDFInputTooLarge, len(content), maxRDFInputSize)
	}
	return nil
}

// CopyRDFContent safely copies RDF content with size validation
func CopyRDFContent(content []byte) ([]byte, error) {
	if err := ValidateRDFInputSize(content); err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, nil
	}
	copied := make([]byte, len(content))
	copy(copied, content)
	return copied, nil
}

// StreamRDFParser is an RDF parser that can parse from a stream with size limits
type StreamRDFParser struct {
	parser  RDFParser
	maxSize int64
}

// NewStreamRDFParser creates a new streaming RDF parser
func NewStreamRDFParser(parser RDFParser, maxSize int64) *StreamRDFParser {
	if maxSize == 0 {
		maxSize = 1 << 20 // 1MB default
	}
	return &StreamRDFParser{
		parser:  parser,
		maxSize: maxSize,
	}
}

// Parse implements RDFParser interface for streaming
func (p *StreamRDFParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	// Validate size first
	if int64(len(content)) > p.maxSize {
		return RDFParseResult{}, fmt.Errorf("%w: input size %d exceeds stream limit %d", ErrRDFInputTooLarge, len(content), p.maxSize)
	}

	return p.parser.Parse(ctx, content, contentType)
}

// SupportedContentTypes implements RDFParser interface
func (p *StreamRDFParser) SupportedContentTypes() []string {
	return p.parser.SupportedContentTypes()
}

// Ensure all interfaces are properly implemented
var _ RDFParser = (*StreamRDFParser)(nil)
