// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 4: RDF graph/index layer.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// RDFGraphIndexLayer implements Layer 4: RDF graph/index layer
// This layer provides RDF parsing, indexing, and query capabilities
// for the Solid runtime.
//
// Key principles:
// - Deterministic RDF parsing and canonicalization
// - Efficient indexing for common Solid patterns
// - Integration with Rust parser boundary (when available)
// - Privacy-safe RDF operations (no sensitive data leakage)
// - Support for multiple RDF formats (Turtle, N-Triples, JSON-LD)
type RDFGraphIndexLayer struct {
	mu sync.RWMutex

	config RDFGraphIndexConfig

	// RDF graphs storage (URI -> graph)
	graphs map[string]*RDFGraph

	// Indexes for efficient querying
	subjectIndex   map[string]map[string]*RDFGraph // subject -> predicate -> graph
	predicateIndex map[string]map[string]*RDFGraph // predicate -> object -> graph
	objectIndex    map[string]map[string]*RDFGraph // object -> subject -> graph
	typeIndex      map[string][]string             // type URI -> resource URIs

	// Graph statistics
	metrics RDFGraphIndexMetrics

	// Logger
	logger *slog.Logger

	// Close state
	closeChan chan struct{}
	closed    bool
}

// RDFGraphIndexConfig holds configuration for the RDF graph/index layer
type RDFGraphIndexConfig struct {
	// MaxGraphSize is the maximum size of a single RDF graph in bytes
	MaxGraphSize int

	// MaxGraphs is the maximum number of graphs to store
	MaxGraphs int

	// EnableCaching enables caching of parsed graphs
	EnableCaching bool

	// CacheSize is the maximum number of cached graphs
	CacheSize int

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultRDFGraphIndexConfig returns a safe default configuration
func DefaultRDFGraphIndexConfig() RDFGraphIndexConfig {
	return RDFGraphIndexConfig{
		MaxGraphSize:  1024 * 1024, // 1MB
		MaxGraphs:     10000,
		EnableCaching: true,
		CacheSize:     1000,
		Logger:        nil,
	}
}

// RDFGraphIndexMetrics holds metrics for the RDF graph/index layer
type RDFGraphIndexMetrics struct {
	mu sync.RWMutex

	// Parse operations
	TotalParses      int64
	SuccessfulParses int64
	FailedParses     int64

	// Index operations
	IndexUpdates int64

	// Query operations
	SubjectQueries   int64
	PredicateQueries int64
	ObjectQueries    int64
	TypeQueries      int64

	// Graph counts
	GraphCount  int64
	TripleCount int64

	// Cache metrics
	CacheHits   int64
	CacheMisses int64
}

// RecordParse records a parse operation
func (m *RDFGraphIndexMetrics) RecordParse(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalParses++
	if success {
		m.SuccessfulParses++
	} else {
		m.FailedParses++
	}
}

// RecordIndexUpdate records an index update
func (m *RDFGraphIndexMetrics) RecordIndexUpdate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.IndexUpdates++
}

// RecordSubjectQuery records a subject query
func (m *RDFGraphIndexMetrics) RecordSubjectQuery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SubjectQueries++
}

// RecordPredicateQuery records a predicate query
func (m *RDFGraphIndexMetrics) RecordPredicateQuery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PredicateQueries++
}

// RecordObjectQuery records an object query
func (m *RDFGraphIndexMetrics) RecordObjectQuery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ObjectQueries++
}

// RecordTypeQuery records a type query
func (m *RDFGraphIndexMetrics) RecordTypeQuery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TypeQueries++
}

// RecordCacheHit records a cache hit
func (m *RDFGraphIndexMetrics) RecordCacheHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheHits++
}

// RecordCacheMiss records a cache miss
func (m *RDFGraphIndexMetrics) RecordCacheMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheMisses++
}

// RDFGraph represents an RDF graph with its triples
type RDFGraph struct {
	// URI is the resource URI that this graph represents
	URI string

	// Triples are the RDF triples in this graph
	Triples []RDFTriple

	// Format is the original RDF format (turtle, ntriples, jsonld)
	Format string

	// Hash is a content hash of the graph for cache invalidation
	Hash string

	// Size is the size in bytes
	Size int

	// LastModified is when the graph was last modified
	LastModified string
}

// RDFTriple represents a single RDF triple
type RDFTriple struct {
	// Subject is the subject of the triple
	Subject string

	// Predicate is the predicate of the triple
	Predicate string

	// Object is the object of the triple
	Object string

	// ObjectType is the type of the object (literal, uri, blank)
	ObjectType RDFObjectType

	// Language is the language tag (for literals)
	Language string

	// Datatype is the datatype URI (for literals)
	Datatype string
}

// RDFObjectType represents the type of an RDF object
type RDFObjectType string

const (
	RDFObjectTypeURI     RDFObjectType = "uri"
	RDFObjectTypeBlank   RDFObjectType = "blank"
	RDFObjectTypeLiteral RDFObjectType = "literal"
)

// RDFFormat represents supported RDF formats
type RDFFormat string

const (
	RDFFormatTurtle   RDFFormat = "text/turtle"
	RDFFormatNTriples RDFFormat = "application/n-triples"
	RDFFormatJSONLD   RDFFormat = "application/ld+json"
	RDFFormatUnknown  RDFFormat = "unknown"
)

// ParseError represents an error during RDF parsing
type ParseError struct {
	// Message describes the error
	Message string

	// Line is the line number where the error occurred
	Line int

	// Column is the column number where the error occurred
	Column int

	// Input is the input that caused the error (truncated for safety)
	Input string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("RDF parse error at line %d, col %d: %s", e.Line, e.Column, e.Message)
}

// ParseResult represents the result of parsing RDF
type ParseResult struct {
	// Graph is the parsed RDF graph
	Graph *RDFGraph

	// Triples is the list of parsed triples
	Triples []RDFTriple

	// Format is the detected RDF format
	Format RDFFormat

	// Warnings contains any parsing warnings
	Warnings []string

	// Error contains any parsing error
	Error error
}

// NewRDFGraphIndexLayer creates a new RDF graph/index layer
func NewRDFGraphIndexLayer(config RDFGraphIndexConfig) *RDFGraphIndexLayer {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	layer := &RDFGraphIndexLayer{
		config:         config,
		graphs:         make(map[string]*RDFGraph),
		subjectIndex:   make(map[string]map[string]*RDFGraph),
		predicateIndex: make(map[string]map[string]*RDFGraph),
		objectIndex:    make(map[string]map[string]*RDFGraph),
		typeIndex:      make(map[string][]string),
		logger:         config.Logger,
		closeChan:      make(chan struct{}),
		closed:         false,
		metrics:        RDFGraphIndexMetrics{},
	}

	config.Logger.Info("RDF graph/index layer initialized",
		"max_graph_size", config.MaxGraphSize,
		"max_graphs", config.MaxGraphs,
		"enable_caching", config.EnableCaching,
		"cache_size", config.CacheSize,
	)

	return layer
}

// Parse parses RDF content and returns a graph
func (r *RDFGraphIndexLayer) Parse(ctx context.Context, uri string, content []byte, contentType string) (*ParseResult, error) {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}
	
	// Validate content type to prevent injection
	if err := ValidateContentType(contentType); err != nil {
		return nil, fmt.Errorf("invalid content type: %w", err)
	}
	
	// Validate content size to prevent DoS attacks
	if err := ValidateResourceSize(int64(len(content))); err != nil {
		return nil, fmt.Errorf("content validation failed: %w", err)
	}

	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return nil, errors.New("RDF graph/index layer is closed")
	}
	r.mu.RUnlock()

	r.metrics.RecordParse(false)

	// Detect format
	format := detectRDFFormat(contentType, content)

	// Parse based on format
	var result *ParseResult
	var err error

	switch format {
	case RDFFormatTurtle:
		result, err = r.parseTurtle(uri, content)
	case RDFFormatNTriples:
		result, err = r.parseNTriples(uri, content)
	case RDFFormatJSONLD:
		result, err = r.parseJSONLD(uri, content)
	default:
		r.metrics.RecordParse(false)
		return nil, fmt.Errorf("unsupported RDF format: %s", format)
	}

	if err != nil {
		r.metrics.RecordParse(false)
		return nil, err
	}

	r.metrics.RecordParse(true)
	r.metrics.RecordIndexUpdate()

	return result, nil
}

// detectRDFFormat detects the RDF format from content type and content
func detectRDFFormat(contentType string, content []byte) RDFFormat {
	// Check content type first
	contentType = strings.ToLower(contentType)

	switch {
	case strings.Contains(contentType, "text/turtle"):
		return RDFFormatTurtle
	case strings.Contains(contentType, "application/n-triples"):
		return RDFFormatNTriples
	case strings.Contains(contentType, "application/ld+json") || strings.Contains(contentType, "application/json"):
		return RDFFormatJSONLD
	}

	// Fall back to content inspection
	contentStr := string(content)
	contentStr = strings.TrimSpace(contentStr)

	if strings.HasPrefix(contentStr, "@prefix") || strings.HasPrefix(contentStr, "PREFIX") {
		return RDFFormatTurtle
	}
	if strings.HasPrefix(contentStr, "<") || strings.HasPrefix(contentStr, "_") {
		return RDFFormatNTriples
	}
	if strings.HasPrefix(contentStr, "{") {
		return RDFFormatJSONLD
	}

	return RDFFormatTurtle // Default to Turtle for Solid
}

// parseTurtle parses Turtle format RDF
// This is a simplified implementation - production would use a proper Turtle parser
func (r *RDFGraphIndexLayer) parseTurtle(uri string, content []byte) (*ParseResult, error) {
	// Simplified Turtle parser for demonstration
	// In production, integrate with Rust parser boundary

	if len(content) > r.config.MaxGraphSize {
		return nil, &ParseError{
			Message: "graph exceeds maximum size",
			Line:    0,
			Column:  0,
			Input:   string(content[:100]) + "...",
		}
	}

	graph := &RDFGraph{
		URI:     uri,
		Triples: []RDFTriple{},
		Format:  "text/turtle",
		Size:    len(content),
	}

	// Simple line-based parsing for demonstration
	lines := strings.Split(string(content), "\n")
	var warnings []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@prefix") || strings.HasPrefix(line, "PREFIX") {
			continue
		}

		// Very simple triple parsing (this would be replaced with proper parsing)
		// Look for patterns like: <subject> <predicate> <object> .
		if strings.HasSuffix(line, ".") {
			// Remove the trailing .
			line = strings.TrimSuffix(line, ".")
			line = strings.TrimSpace(line)

			// Split by whitespace, but this is very naive
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				subject := parts[0]
				predicate := parts[1]
				object := strings.Join(parts[2:], " ")

				// Clean up the parts
				subject = cleanRDFTerm(subject)
				predicate = cleanRDFTerm(predicate)
				object = cleanRDFTerm(object)

				// Determine object type
				objType := determineObjectType(object)

				graph.Triples = append(graph.Triples, RDFTriple{
					Subject:    subject,
					Predicate:  predicate,
					Object:     object,
					ObjectType: objType,
				})

				// Index type information
				if predicate == "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>" || predicate == "a" {
					r.typeIndex[object] = append(r.typeIndex[object], uri)
				}
			}
		}
	}

	// Calculate hash
	graph.Hash = hashGraph(graph.Triples)

	result := &ParseResult{
		Graph:    graph,
		Triples:  graph.Triples,
		Format:   RDFFormatTurtle,
		Warnings: warnings,
	}

	// Add to indexes
	r.addToIndexes(graph)

	return result, nil
}

// parseNTriples parses N-Triples format RDF
func (r *RDFGraphIndexLayer) parseNTriples(uri string, content []byte) (*ParseResult, error) {
	// Similar simplified implementation
	return r.parseTurtle(uri, content) // Reuse for now
}

// parseJSONLD parses JSON-LD format RDF
func (r *RDFGraphIndexLayer) parseJSONLD(uri string, content []byte) (*ParseResult, error) {
	// Similar simplified implementation
	return r.parseTurtle(uri, content) // Reuse for now
}

// cleanRDFTerm removes angle brackets and quotes from RDF terms
func cleanRDFTerm(term string) string {
	term = strings.TrimSpace(term)
	term = strings.TrimPrefix(term, "<")
	term = strings.TrimSuffix(term, ">")
	term = strings.TrimPrefix(term, "\"")
	term = strings.TrimSuffix(term, "\"")
	return term
}

// determineObjectType determines the type of an RDF object
func determineObjectType(obj string) RDFObjectType {
	if strings.HasPrefix(obj, "<") && strings.HasSuffix(obj, ">") {
		return RDFObjectTypeURI
	}
	if strings.HasPrefix(obj, "_") {
		return RDFObjectTypeBlank
	}
	return RDFObjectTypeLiteral
}

// hashGraph creates a hash of a graph's triples
func hashGraph(triples []RDFTriple) string {
	h := sha256.New()
	for _, triple := range triples {
		h.Write([]byte(triple.Subject))
		h.Write([]byte(triple.Predicate))
		h.Write([]byte(triple.Object))
		h.Write([]byte(triple.ObjectType))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// addToIndexes adds a graph to all indexes
func (r *RDFGraphIndexLayer) addToIndexes(graph *RDFGraph) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}

	// Check limits
	if len(r.graphs) >= r.config.MaxGraphs {
		r.logger.Warn("RDF graph limit reached, not indexing graph",
			"uri", graph.URI,
			"max_graphs", r.config.MaxGraphs,
		)
		return
	}

	// Store the graph
	r.graphs[graph.URI] = graph

	// Update triple count
	r.metrics.TripleCount += int64(len(graph.Triples))
	r.metrics.GraphCount++

	// Index by subject
	if r.subjectIndex[graph.URI] == nil {
		r.subjectIndex[graph.URI] = make(map[string]*RDFGraph)
	}

	// Index by predicate
	if r.predicateIndex[graph.URI] == nil {
		r.predicateIndex[graph.URI] = make(map[string]*RDFGraph)
	}

	// Index by object
	if r.objectIndex[graph.URI] == nil {
		r.objectIndex[graph.URI] = make(map[string]*RDFGraph)
	}

	// Index individual triples
	for _, triple := range graph.Triples {
		// Subject index
		if r.subjectIndex[triple.Subject] == nil {
			r.subjectIndex[triple.Subject] = make(map[string]*RDFGraph)
		}
		r.subjectIndex[triple.Subject][triple.Predicate] = graph

		// Predicate index
		if r.predicateIndex[triple.Predicate] == nil {
			r.predicateIndex[triple.Predicate] = make(map[string]*RDFGraph)
		}
		r.predicateIndex[triple.Predicate][triple.Object] = graph

		// Object index
		if r.objectIndex[triple.Object] == nil {
			r.objectIndex[triple.Object] = make(map[string]*RDFGraph)
		}
		r.objectIndex[triple.Object][triple.Subject] = graph
	}

	r.logger.Debug("RDF graph indexed",
		"uri", graph.URI,
		"triple_count", len(graph.Triples),
		"format", graph.Format,
	)
}

// GetGraph retrieves a graph by URI
func (r *RDFGraphIndexLayer) GetGraph(uri string) (*RDFGraph, error) {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, errors.New("RDF graph/index layer is closed")
	}

	graph, exists := r.graphs[uri]
	if !exists {
		return nil, fmt.Errorf("graph %q not found", uri)
	}

	// Return a copy for thread safety
	return r.copyGraph(graph), nil
}

// copyGraph creates a copy of an RDF graph
func (r *RDFGraphIndexLayer) copyGraph(graph *RDFGraph) *RDFGraph {
	if graph == nil {
		return nil
	}

	copiedTriples := make([]RDFTriple, len(graph.Triples))
	for i, triple := range graph.Triples {
		copiedTriples[i] = RDFTriple{
			Subject:    triple.Subject,
			Predicate:  triple.Predicate,
			Object:     triple.Object,
			ObjectType: triple.ObjectType,
			Language:   triple.Language,
			Datatype:   triple.Datatype,
		}
	}

	return &RDFGraph{
		URI:          graph.URI,
		Triples:      copiedTriples,
		Format:       graph.Format,
		Hash:         graph.Hash,
		Size:         graph.Size,
		LastModified: graph.LastModified,
	}
}

// QueryBySubject finds graphs containing triples with a specific subject
func (r *RDFGraphIndexLayer) QueryBySubject(subject string) ([]*RDFGraph, error) {
	// Validate RDF term to prevent injection attacks
	if err := ValidateRDFTerm(subject); err != nil {
		return nil, fmt.Errorf("invalid subject: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, errors.New("RDF graph/index layer is closed")
	}

	r.metrics.RecordSubjectQuery()

	predicateMap, exists := r.subjectIndex[subject]
	if !exists {
		return []*RDFGraph{}, nil
	}

	graphs := make([]*RDFGraph, 0, len(predicateMap))
	for _, graph := range predicateMap {
		graphs = append(graphs, r.copyGraph(graph))
	}

	return graphs, nil
}

// QueryByPredicate finds graphs containing triples with a specific predicate
func (r *RDFGraphIndexLayer) QueryByPredicate(predicate string) ([]*RDFGraph, error) {
	// Validate RDF term to prevent injection attacks
	if err := ValidateRDFTerm(predicate); err != nil {
		return nil, fmt.Errorf("invalid predicate: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, errors.New("RDF graph/index layer is closed")
	}

	r.metrics.RecordPredicateQuery()

	objectMap, exists := r.predicateIndex[predicate]
	if !exists {
		return []*RDFGraph{}, nil
	}

	graphs := make([]*RDFGraph, 0, len(objectMap))
	for _, graph := range objectMap {
		graphs = append(graphs, r.copyGraph(graph))
	}

	return graphs, nil
}

// QueryByObject finds graphs containing triples with a specific object
func (r *RDFGraphIndexLayer) QueryByObject(object string) ([]*RDFGraph, error) {
	// Validate RDF term to prevent injection attacks
	if err := ValidateRDFTerm(object); err != nil {
		return nil, fmt.Errorf("invalid object: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, errors.New("RDF graph/index layer is closed")
	}

	r.metrics.RecordObjectQuery()

	subjectMap, exists := r.objectIndex[object]
	if !exists {
		return []*RDFGraph{}, nil
	}

	graphs := make([]*RDFGraph, 0, len(subjectMap))
	for _, graph := range subjectMap {
		graphs = append(graphs, r.copyGraph(graph))
	}

	return graphs, nil
}

// QueryByType finds resources of a specific RDF type
func (r *RDFGraphIndexLayer) QueryByType(rdfType string) ([]string, error) {
	// Validate RDF type term to prevent injection attacks
	if err := ValidateRDFTerm(rdfType); err != nil {
		return nil, fmt.Errorf("invalid RDF type: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, errors.New("RDF graph/index layer is closed")
	}

	r.metrics.RecordTypeQuery()

	uris, exists := r.typeIndex[rdfType]
	if !exists {
		return []string{}, nil
	}

	// Return a copy
	result := make([]string, len(uris))
	copy(result, uris)
	return result, nil
}

// AddGraph adds a pre-parsed graph to the index
func (r *RDFGraphIndexLayer) AddGraph(graph *RDFGraph) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return errors.New("RDF graph/index layer is closed")
	}

	if graph == nil {
		return errors.New("graph cannot be nil")
	}

	// Check size
	if graph.Size > r.config.MaxGraphSize {
		return fmt.Errorf("graph exceeds maximum size: %d > %d", graph.Size, r.config.MaxGraphSize)
	}

	// Check count
	if len(r.graphs) >= r.config.MaxGraphs {
		return fmt.Errorf("maximum graph count reached: %d", r.config.MaxGraphs)
	}

	// Add to indexes
	r.addToIndexes(graph)

	return nil
}

// RemoveGraph removes a graph from the index
func (r *RDFGraphIndexLayer) RemoveGraph(uri string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return errors.New("RDF graph/index layer is closed")
	}

	// Remove from main storage
	if graph, exists := r.graphs[uri]; exists {
		// Remove from subject index
		for _, triple := range graph.Triples {
			if subjectMap, exists := r.subjectIndex[triple.Subject]; exists {
				delete(subjectMap, triple.Predicate)
				if len(subjectMap) == 0 {
					delete(r.subjectIndex, triple.Subject)
				}
			}

			// Remove from predicate index
			if predicateMap, exists := r.predicateIndex[triple.Predicate]; exists {
				delete(predicateMap, triple.Object)
				if len(predicateMap) == 0 {
					delete(r.predicateIndex, triple.Predicate)
				}
			}

			// Remove from object index
			if objectMap, exists := r.objectIndex[triple.Object]; exists {
				delete(objectMap, triple.Subject)
				if len(objectMap) == 0 {
					delete(r.objectIndex, triple.Object)
				}
			}

			// Remove from type index if this was a type triple
			if triple.Predicate == "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>" || triple.Predicate == "a" {
				if uris, exists := r.typeIndex[triple.Object]; exists {
					newURIs := make([]string, 0, len(uris))
					for _, u := range uris {
						if u != uri {
							newURIs = append(newURIs, u)
						}
					}
					if len(newURIs) == 0 {
						delete(r.typeIndex, triple.Object)
					} else {
						r.typeIndex[triple.Object] = newURIs
					}
				}
			}
		}

		// Update metrics
		r.metrics.TripleCount -= int64(len(graph.Triples))
		r.metrics.GraphCount--

		delete(r.graphs, uri)
		r.logger.Debug("RDF graph removed", "uri", uri)
	}

	return nil
}

// UpdateGraph updates an existing graph
func (r *RDFGraphIndexLayer) UpdateGraph(graph *RDFGraph) error {
	if graph == nil {
		return errors.New("graph cannot be nil")
	}

	// Remove old version first
	if err := r.RemoveGraph(graph.URI); err != nil {
		// If it doesn't exist, that's okay
		if !strings.Contains(err.Error(), "not found") {
			return err
		}
	}

	// Add new version
	return r.AddGraph(graph)
}

// GetMetrics returns the current metrics
func (r *RDFGraphIndexLayer) GetMetrics() *RDFGraphIndexMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return &r.metrics
}

// Size returns the current size of the indexes
func (r *RDFGraphIndexLayer) Size() (int, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.graphs), int(r.metrics.TripleCount)
}

// Close closes the RDF graph/index layer
func (r *RDFGraphIndexLayer) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	r.closed = true
	close(r.closeChan)

	// Clear all data
	r.graphs = nil
	r.subjectIndex = nil
	r.predicateIndex = nil
	r.objectIndex = nil
	r.typeIndex = nil

	r.logger.Info("RDF graph/index layer closed")
	return nil
}

// IsClosed returns true if the layer is closed
func (r *RDFGraphIndexLayer) IsClosed() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.closed
}
