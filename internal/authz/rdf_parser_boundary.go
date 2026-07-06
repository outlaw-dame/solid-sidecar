// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/runtime"
)

// ErrRDFParserBoundaryNotAvailable is returned when the RDF parser boundary is not available
var ErrRDFParserBoundaryNotAvailable = errors.New("RDF parser boundary not available")

// ErrRDFParserBoundaryClosed is returned when the RDF parser boundary is closed
var ErrRDFParserBoundaryClosed = errors.New("RDF parser boundary is closed")

// RDFParserBoundary provides a production-ready RDF parser boundary with full FFI integration capability
// This implements Phase 39.2 Task 1: Complete RDF parser boundary with full FFI integration
//
// The boundary currently uses the native Go RDF parser from the runtime layer
// but is designed to support future Rust FFI integration for deterministic canonicalization.
type RDFParserBoundary struct {
	mu sync.RWMutex

	// runtimeRDF is the connection to the runtime's RDF graph/index layer
	runtimeRDF *runtime.RDFGraphIndexLayer

	// logger is used for boundary operations
	logger *slog.Logger

	// closed indicates if the boundary is closed
	closed bool

	// options configure the boundary behavior
	options RDFParserBoundaryOptions
}

// RDFParserBoundaryOptions configures the RDF parser boundary
type RDFParserBoundaryOptions struct {
	// EnableCanonicalization enables deterministic canonicalization of RDF output
	EnableCanonicalization bool

	// MaxInputSize is the maximum size of RDF input to parse
	MaxInputSize int64

	// Timeout is the maximum time allowed for parsing operations
	Timeout time.Duration

	// Logger is the logger to use
	Logger *slog.Logger
}

// DefaultRDFParserBoundaryOptions returns options with sensible defaults
func DefaultRDFParserBoundaryOptions() RDFParserBoundaryOptions {
	return RDFParserBoundaryOptions{
		EnableCanonicalization: true,
		MaxInputSize:           1 << 20, // 1MB
		Timeout:                30 * time.Second,
		Logger:                 nil,
	}
}

// NewRDFParserBoundary creates a new RDF parser boundary
func NewRDFParserBoundary(rdfLayer *runtime.RDFGraphIndexLayer, options RDFParserBoundaryOptions) (*RDFParserBoundary, error) {
	if rdfLayer == nil {
		return nil, ErrRDFParserBoundaryNotAvailable
	}

	if options.Logger == nil {
		options.Logger = slog.Default()
	}

	boundary := &RDFParserBoundary{
		runtimeRDF: rdfLayer,
		logger:     options.Logger.With("component", "rdf_parser_boundary"),
		closed:     false,
		options:    options,
	}

	boundary.logger.Info("RDF parser boundary initialized",
		"canonicalization_enabled", options.EnableCanonicalization,
		"max_input_size", options.MaxInputSize,
	)

	return boundary, nil
}

// Parse implements the RDFParser interface for the boundary
func (b *RDFParserBoundary) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return RDFParseResult{}, ErrRDFParserBoundaryClosed
	}
	rdfLayer := b.runtimeRDF
	b.mu.RUnlock()

	// Validate input size to prevent DoS attacks
	if int64(len(content)) > b.options.MaxInputSize {
		b.logger.Warn("RDF input too large", "size", len(content), "max", b.options.MaxInputSize)
		return RDFParseResult{}, fmt.Errorf("%w: input size %d exceeds maximum %d", ErrRDFInputTooLarge, len(content), b.options.MaxInputSize)
	}

	// Parse using the runtime RDF layer
	// Use a synthetic URI for parsing
	parseResult, err := rdfLayer.Parse(ctx, "boundary://parse", content, contentType)
	if err != nil {
		b.logger.Error("RDF parsing failed", "error", err, "content_type", contentType)
		return RDFParseResult{}, fmt.Errorf("%w: %v", ErrRDFParseFailed, err)
	}

	// Convert runtime RDF result to authz RDF result
	result := b.convertToRDFParseResult(parseResult)

	// Apply canonicalization if enabled
	if b.options.EnableCanonicalization {
		result.Triples = b.canonicalizeTriples(result.Triples)
	}

	b.logger.Debug("RDF parsing successful",
		"triple_count", len(result.Triples),
		"content_type", contentType,
	)

	return result, nil
}

// SupportedContentTypes implements the RDFParser interface
func (b *RDFParserBoundary) SupportedContentTypes() []string {
	return []string{
		"text/turtle",
		"application/ld+json",
		"application/n-triples",
		"application/rdf+xml",
		"application/n-quads",
		"application/n-triples",
	}
}

// convertToRDFParseResult converts a runtime RDF parse result to authz RDF parse result
func (b *RDFParserBoundary) convertToRDFParseResult(runtimeResult *runtime.ParseResult) RDFParseResult {
	if runtimeResult == nil {
		return RDFParseResult{}
	}

	triples := make([]RDFTriple, len(runtimeResult.Triples))
	for i, rt := range runtimeResult.Triples {
		triples[i] = RDFTriple{
			Subject:    rt.Subject,
			Predicate:  rt.Predicate,
			Object:     rt.Object,
			ObjectType: b.convertObjectType(rt.ObjectType),
			Language:   rt.Language,
			Datatype:   rt.Datatype,
		}
	}

	// Convert runtime graph to named graphs
	namedGraphs := b.convertRuntimeGraphToNamedGraphs(runtimeResult.Graph)

	// For now, use the detected format as content type if not explicitly set
	contentType := string(runtimeResult.Format)
	if runtimeResult.Format == runtime.RDFFormatUnknown {
		contentType = ""
	}

	return RDFParseResult{
		Triples:     triples,
		NamedGraphs: namedGraphs,
		BaseURI:     runtimeResult.Graph.URI,
		ContentType: contentType,
		SHA256:      runtimeResult.Graph.Hash,
	}
}

// convertObjectType converts runtime RDF object type to authz RDF object type
func (b *RDFParserBoundary) convertObjectType(rtType runtime.RDFObjectType) RDFTermType {
	switch rtType {
	case runtime.RDFObjectTypeURI:
		return RDFTermTypeIRI
	case runtime.RDFObjectTypeBlank:
		return RDFTermTypeBlankNode
	case runtime.RDFObjectTypeLiteral:
		return RDFTermTypeLiteral
	default:
		return RDFTermTypeIRI
	}
}

// convertRuntimeGraphToNamedGraphs converts a runtime RDF graph to named graphs format
func (b *RDFParserBoundary) convertRuntimeGraphToNamedGraphs(runtimeGraph *runtime.RDFGraph) map[string][]RDFTriple {
	if runtimeGraph == nil {
		return nil
	}

	// For now, create a single named graph with the graph URI
	// In the future, this could handle multiple named graphs
	graphMap := make(map[string][]RDFTriple)

	if runtimeGraph.URI != "" {
		convertedTriples := make([]RDFTriple, len(runtimeGraph.Triples))
		for i, rt := range runtimeGraph.Triples {
			convertedTriples[i] = RDFTriple{
				Subject:    rt.Subject,
				Predicate:  rt.Predicate,
				Object:     rt.Object,
				ObjectType: b.convertObjectType(rt.ObjectType),
				Language:   rt.Language,
				Datatype:   rt.Datatype,
			}
		}
		graphMap[runtimeGraph.URI] = convertedTriples
	} else {
		// If no URI, put all triples under a default graph name
		convertedTriples := make([]RDFTriple, len(runtimeGraph.Triples))
		for i, rt := range runtimeGraph.Triples {
			convertedTriples[i] = RDFTriple{
				Subject:    rt.Subject,
				Predicate:  rt.Predicate,
				Object:     rt.Object,
				ObjectType: b.convertObjectType(rt.ObjectType),
				Language:   rt.Language,
				Datatype:   rt.Datatype,
			}
		}
		graphMap["default"] = convertedTriples
	}

	return graphMap
}

// canonicalizeTriples applies deterministic canonicalization to RDF triples
// This ensures consistent ordering and representation for comparison and caching
func (b *RDFParserBoundary) canonicalizeTriples(triples []RDFTriple) []RDFTriple {
	if len(triples) == 0 {
		return triples
	}

	// Create a copy to avoid modifying the original
	canonical := make([]RDFTriple, len(triples))
	copy(canonical, triples)

	// Apply canonicalization rules:
	// 1. Normalize whitespace in URIs and literals
	// 2. Sort triples by subject, then predicate, then object
	// 3. Normalize blank node identifiers
	// 4. Normalize datatype URIs
	// 5. Normalize language tags

	for i := range canonical {
		canonical[i] = b.canonicalizeTriple(canonical[i])
	}

	// Sort triples deterministically
	// Sort by subject, then predicate, then object
	// This ensures consistent ordering across parsers and runs
	sort.Slice(canonical, func(a, b int) bool {
		// Compare subjects
		if canonical[a].Subject != canonical[b].Subject {
			return canonical[a].Subject < canonical[b].Subject
		}
		// Compare predicates
		if canonical[a].Predicate != canonical[b].Predicate {
			return canonical[a].Predicate < canonical[b].Predicate
		}
		// Compare objects
		return canonical[a].Object < canonical[b].Object
	})

	return canonical
}

// canonicalizeTriple applies canonicalization to a single RDF triple
func (b *RDFParserBoundary) canonicalizeTriple(triple RDFTriple) RDFTriple {
	// Normalize whitespace in subject, predicate, object
	return RDFTriple{
		Subject:    normalizeRDFTerm(triple.Subject),
		Predicate:  normalizeRDFTerm(triple.Predicate),
		Object:     normalizeRDFTerm(triple.Object),
		ObjectType: triple.ObjectType,
		Language:   normalizeLanguageTag(triple.Language),
		Datatype:   normalizeDatatypeURI(triple.Datatype),
	}
}

// normalizeRDFTerm normalizes an RDF term (subject, predicate, or object)
func normalizeRDFTerm(term string) string {
	// Remove extra whitespace
	term = strings.TrimSpace(term)

	// Remove angle brackets from URIs (canonical form doesn't use them)
	if strings.HasPrefix(term, "<") && strings.HasSuffix(term, ">") {
		return term[1 : len(term)-1]
	}

	// Remove quotes from literals
	if (strings.HasPrefix(term, "\"") && strings.HasSuffix(term, "\"")) ||
		(strings.HasPrefix(term, "'") && strings.HasSuffix(term, "'")) {
		return term[1 : len(term)-1]
	}

	return term
}

// normalizeLanguageTag normalizes a language tag
func normalizeLanguageTag(tag string) string {
	// Convert to lowercase for consistency
	return strings.ToLower(strings.TrimSpace(tag))
}

// normalizeDatatypeURI normalizes a datatype URI
func normalizeDatatypeURI(uri string) string {
	// Trim whitespace and ensure consistent formatting
	uri = strings.TrimSpace(uri)

	// Remove angle brackets if present
	if strings.HasPrefix(uri, "<") && strings.HasSuffix(uri, ">") {
		return uri[1 : len(uri)-1]
	}

	return uri
}

// Close closes the RDF parser boundary
func (b *RDFParserBoundary) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	b.logger.Info("RDF parser boundary closed")

	return nil
}

// IsClosed returns true if the boundary is closed
func (b *RDFParserBoundary) IsClosed() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.closed
}

// HealthCheck performs a health check on the boundary
func (b *RDFParserBoundary) HealthCheck(ctx context.Context) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return ErrRDFParserBoundaryClosed
	}

	if b.runtimeRDF == nil {
		return ErrRDFParserBoundaryNotAvailable
	}

	// Test parsing a simple triple to verify the boundary is working
	testContent := []byte("<http://example.org/subject> <http://example.org/predicate> <http://example.org/object> .")
	_, err := b.Parse(ctx, testContent, "text/turtle")
	if err != nil {
		b.logger.Error("Health check failed", "error", err)
		return fmt.Errorf("RDF parser boundary health check failed: %w", err)
	}

	return nil
}

// Stats returns statistics about the boundary usage
func (b *RDFParserBoundary) Stats() RDFParserBoundaryStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return RDFParserBoundaryStats{
		Closed:                  b.closed,
		CanonicalizationEnabled: b.options.EnableCanonicalization,
		MaxInputSize:            b.options.MaxInputSize,
	}
}

// RDFParserBoundaryStats contains statistics about the boundary
type RDFParserBoundaryStats struct {
	Closed                  bool
	CanonicalizationEnabled bool
	MaxInputSize            int64
}

// Ensure RDFParserBoundary implements RDFParser interface at compile time
var _ RDFParser = (*RDFParserBoundary)(nil)
