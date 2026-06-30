// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockRDFParser is a mock implementation of RDFParser for testing
type mockRDFParser struct {
	supportedTypes []string
	parseFunc      func(ctx context.Context, content []byte, contentType string) (RDFParseResult, error)
}

func (m *mockRDFParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	if m.parseFunc != nil {
		return m.parseFunc(ctx, content, contentType)
	}
	// Default mock behavior
	return RDFParseResult{
		Triples: []RDFTriple{
			{
				Subject:    "https://example.org/subject",
				Predicate:  "https://example.org/predicate",
				Object:     "https://example.org/object",
				ObjectType: RDFTermTypeIRI,
			},
		},
		ContentType: contentType,
		SHA256:      "test-hash",
	}, nil
}

func (m *mockRDFParser) SupportedContentTypes() []string {
	if m.supportedTypes != nil {
		return m.supportedTypes
	}
	return []string{"text/turtle", "application/ld+json"}
}

// mockFailingRDFParser is a mock parser that always fails
type mockFailingRDFParser struct{}

func (m *mockFailingRDFParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	return RDFParseResult{}, errors.New("mock parse error")
}

func (m *mockFailingRDFParser) SupportedContentTypes() []string {
	return []string{"text/turtle"}
}

// mockControlCharRDFParser returns triples with control characters
type mockControlCharRDFParser struct{}

func (m *mockControlCharRDFParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	return RDFParseResult{
		Triples: []RDFTriple{
			{
				Subject:    "https://example.org/subject\x00",
				Predicate:  "https://example.org/predicate",
				Object:     "https://example.org/object",
				ObjectType: RDFTermTypeIRI,
			},
		},
		ContentType: contentType,
	}, nil
}

func (m *mockControlCharRDFParser) SupportedContentTypes() []string {
	return []string{"text/turtle"}
}

// TestRDFParserRegistryCreation tests creating a parser registry
func TestRDFParserRegistryCreation(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	if registry == nil {
		t.Fatal("registry is nil")
	}
	if len(registry.parsers) != 0 {
		t.Errorf("expected 0 parsers, got %d", len(registry.parsers))
	}
}

// TestRDFParserRegistryRegister tests registering parsers
func TestRDFParserRegistryRegister(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())

	parser1 := &mockRDFParser{supportedTypes: []string{"text/turtle"}}
	parser2 := &mockRDFParser{supportedTypes: []string{"application/ld+json"}}

	registry.Register(parser1)
	registry.Register(parser2)

	if len(registry.parsers) != 2 {
		t.Errorf("expected 2 parsers, got %d", len(registry.parsers))
	}
	if len(registry.contentTypeMap) != 2 {
		t.Errorf("expected 2 content type mappings, got %d", len(registry.contentTypeMap))
	}
}

// TestRDFParserRegistryParse tests parsing with a registered parser
func TestRDFParserRegistryParse(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())

	parser := &mockRDFParser{
		supportedTypes: []string{"text/turtle"},
		parseFunc: func(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
			return RDFParseResult{
				Triples: []RDFTriple{
					{
						Subject:    "https://example.org/test",
						Predicate:  "a",
						Object:     "https://example.org/Resource",
						ObjectType: RDFTermTypeIRI,
					},
				},
				ContentType: "text/turtle",
				SHA256:      "abc123",
			}, nil
		},
	}
	registry.Register(parser)

	result, err := registry.Parse(context.Background(), []byte("test content"), "text/turtle")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(result.Triples) != 1 {
		t.Errorf("expected 1 triple, got %d", len(result.Triples))
	}
	if result.Triples[0].Subject != "https://example.org/test" {
		t.Errorf("expected subject %q, got %q", "https://example.org/test", result.Triples[0].Subject)
	}
	if result.ContentType != "text/turtle" {
		t.Errorf("expected content type %q, got %q", "text/turtle", result.ContentType)
	}
}

// TestRDFParserRegistryParseUnsupportedContentType tests error for unsupported content type
func TestRDFParserRegistryParseUnsupportedContentType(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())

	parser := &mockRDFParser{supportedTypes: []string{"text/turtle"}}
	registry.Register(parser)

	_, err := registry.Parse(context.Background(), []byte("test"), "text/html")
	if err == nil {
		t.Fatal("expected error for unsupported content type, got nil")
	}
	if !errors.Is(err, ErrRDFContentTypeNotSupported) {
		t.Errorf("expected ErrRDFContentTypeNotSupported, got %v", err)
	}
}

// TestRDFParserRegistryParseContentTypeDetection tests automatic content type detection
func TestRDFParserRegistryParseContentTypeDetection(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())

	parser := &mockRDFParser{
		supportedTypes: []string{"text/turtle"},
		parseFunc: func(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
			return RDFParseResult{
				Triples:     []RDFTriple{},
				ContentType: contentType,
			}, nil
		},
	}
	registry.Register(parser)

	// Content that looks like Turtle should be detected and parsed
	turtleContent := []byte("@prefix ex: <http://example.org/> .")
	result, err := registry.Parse(context.Background(), turtleContent, "")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if result.ContentType != "text/turtle" {
		t.Errorf("expected detected content type text/turtle, got %q", result.ContentType)
	}
}

// TestRDFParserRegistryParseJSONLDDetection tests JSON-LD detection
func TestRDFParserRegistryParseJSONLDDetection(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())

	parser := &mockRDFParser{
		supportedTypes: []string{"application/ld+json"},
		parseFunc: func(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
			return RDFParseResult{
				Triples:     []RDFTriple{},
				ContentType: contentType,
			}, nil
		},
	}
	registry.Register(parser)

	// Content that looks like JSON-LD should be detected
	jsonldContent := []byte(`{"@context": "http://example.org/", "@id": "test"}`)
	result, err := registry.Parse(context.Background(), jsonldContent, "application/octet-stream")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if result.ContentType != "application/ld+json" {
		t.Errorf("expected detected content type application/ld+json, got %q", result.ContentType)
	}
}

// TestRDFParserRegistryParseParserNotFound tests error when no parser is found
func TestRDFParserRegistryParseParserNotFound(t *testing.T) {
	// Use options without AllowedContentTypes to avoid content type filtering
	options := DefaultRDFParserOptions()
	options.AllowedContentTypes = []string{} // Allow all content types

	registry := NewRDFParserRegistry(options)

	// Register a parser but ask for a different content type
	parser := &mockRDFParser{supportedTypes: []string{"text/turtle"}}
	registry.Register(parser)

	_, err := registry.Parse(context.Background(), []byte("test"), "application/xml")
	if err == nil {
		t.Fatal("expected error for no parser found, got nil")
	}
	if !errors.Is(err, ErrRDFParserNotFound) {
		t.Errorf("expected ErrRDFParserNotFound, got %v", err)
	}
}

// TestRDFParserRegistryParseInputTooLarge tests error for input that's too large
func TestRDFParserRegistryParseInputTooLarge(t *testing.T) {
	options := DefaultRDFParserOptions()
	options.MaxInputSize = 100 // Very small limit

	registry := NewRDFParserRegistry(options)
	parser := &mockRDFParser{supportedTypes: []string{"text/turtle"}}
	registry.Register(parser)

	// Create content larger than the limit
	largeContent := make([]byte, 200)
	for i := range largeContent {
		largeContent[i] = 'a'
	}

	_, err := registry.Parse(context.Background(), largeContent, "text/turtle")
	if err == nil {
		t.Fatal("expected error for input too large, got nil")
	}
	if !errors.Is(err, ErrRDFInputTooLarge) {
		t.Errorf("expected ErrRDFInputTooLarge, got %v", err)
	}
}

// TestRDFParserRegistryParseWithFailingParser tests error handling with failing parser
func TestRDFParserRegistryParseWithFailingParser(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())

	failingParser := &mockFailingRDFParser{}
	registry.Register(failingParser)

	_, err := registry.Parse(context.Background(), []byte("test"), "text/turtle")
	if err == nil {
		t.Fatal("expected error from failing parser, got nil")
	}
	if !errors.Is(err, ErrRDFParseFailed) {
		t.Errorf("expected ErrRDFParseFailed, got %v", err)
	}
}

// TestRDFParserRegistryParseWithControlChars tests validation of control characters
func TestRDFParserRegistryParseWithControlChars(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())

	controlCharParser := &mockControlCharRDFParser{}
	registry.Register(controlCharParser)

	_, err := registry.Parse(context.Background(), []byte("test"), "text/turtle")
	if err == nil {
		t.Fatal("expected error for control characters, got nil")
	}
	if !errors.Is(err, ErrRDFParseFailed) {
		t.Errorf("expected ErrRDFParseFailed, got %v", err)
	}
}

// TestRDFParserRegistryTimeout tests timeout handling
func TestRDFParserRegistryTimeout(t *testing.T) {
	options := DefaultRDFParserOptions()
	options.Timeout = 1 * time.Nanosecond // Very short timeout

	registry := NewRDFParserRegistry(options)

	// Create a parser that takes too long and respects context
	slowParser := &mockRDFParser{
		supportedTypes: []string{"text/turtle"},
		parseFunc: func(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
			select {
			case <-ctx.Done():
				return RDFParseResult{}, ctx.Err()
			case <-time.After(10 * time.Millisecond):
				return RDFParseResult{}, nil
			}
		},
	}
	registry.Register(slowParser)

	ctx := context.Background()
	_, err := registry.Parse(ctx, []byte("test"), "text/turtle")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, ErrRDFParseFailed) {
		t.Errorf("expected ErrRDFParseFailed for timeout, got %v", err)
	}
}

// TestValidateRDFInputSize tests input size validation
func TestValidateRDFInputSize(t *testing.T) {
	testCases := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"small input", 100, false},
		{"at limit", maxRDFInputSize, false},
		{"over limit", maxRDFInputSize + 1, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := make([]byte, tc.size)
			err := ValidateRDFInputSize(content)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateRDFInputSize() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestCopyRDFContent tests safe content copying
func TestCopyRDFContent(t *testing.T) {
	testCases := []struct {
		name    string
		content []byte
		wantErr bool
	}{
		{"empty", nil, false},
		{"empty slice", []byte{}, false},
		{"small", []byte("test"), false},
		{"at limit", make([]byte, maxRDFInputSize), false},
		{"over limit", make([]byte, maxRDFInputSize+1), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			copied, err := CopyRDFContent(tc.content)
			if (err != nil) != tc.wantErr {
				t.Errorf("CopyRDFContent() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && len(copied) != len(tc.content) {
				t.Errorf("CopyRDFContent() length = %d, want %d", len(copied), len(tc.content))
			}
			// Verify copy is independent
			if !tc.wantErr && len(tc.content) > 0 {
				copied[0] = 'X'
				if tc.content[0] == 'X' {
					t.Error("CopyRDFContent() returned reference to original content")
				}
			}
		})
	}
}

// TestStreamRDFParser tests the streaming parser wrapper
func TestStreamRDFParser(t *testing.T) {
	mockParser := &mockRDFParser{supportedTypes: []string{"text/turtle"}}
	streamParser := NewStreamRDFParser(mockParser, 100)

	// Test normal parsing within limit
	result, err := streamParser.Parse(context.Background(), []byte("test"), "text/turtle")
	if err != nil {
		t.Fatalf("stream parse failed: %v", err)
	}
	if len(result.Triples) != 1 {
		t.Errorf("expected 1 triple, got %d", len(result.Triples))
	}

	// Test size limit
	largeContent := make([]byte, 200)
	for i := range largeContent {
		largeContent[i] = 'a'
	}

	_, err = streamParser.Parse(context.Background(), largeContent, "text/turtle")
	if err == nil {
		t.Fatal("expected error for stream size limit, got nil")
	}
	if !errors.Is(err, ErrRDFInputTooLarge) {
		t.Errorf("expected ErrRDFInputTooLarge, got %v", err)
	}
}

// TestStreamRDFParserSupportedContentTypes tests supported content types
func TestStreamRDFParserSupportedContentTypes(t *testing.T) {
	mockParser := &mockRDFParser{supportedTypes: []string{"text/turtle", "application/ld+json"}}
	streamParser := NewStreamRDFParser(mockParser, 100)

	supported := streamParser.SupportedContentTypes()
	if len(supported) != 2 {
		t.Errorf("expected 2 supported types, got %d", len(supported))
	}
}

// TestDefaultRDFParserOptions tests default options
func TestDefaultRDFParserOptions(t *testing.T) {
	options := DefaultRDFParserOptions()

	if options.MaxInputSize != 1<<20 {
		t.Errorf("expected default max input size 1MB, got %d", options.MaxInputSize)
	}
	if options.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", options.Timeout)
	}
	if len(options.AllowedContentTypes) == 0 {
		t.Error("expected allowed content types to be set")
	}
	if len(options.DisallowedContentTypes) == 0 {
		t.Error("expected disallowed content types to be set")
	}
}

// TestRDFParserRegistryAllowedDisallowedContentTypes tests content type filtering
func TestRDFParserRegistryAllowedDisallowedContentTypes(t *testing.T) {
	options := DefaultRDFParserOptions()
	options.AllowedContentTypes = []string{"text/turtle"}
	options.DisallowedContentTypes = []string{"text/turtle"} // Disallowed takes precedence

	registry := NewRDFParserRegistry(options)
	parser := &mockRDFParser{supportedTypes: []string{"text/turtle"}}
	registry.Register(parser)

	_, err := registry.Parse(context.Background(), []byte("test"), "text/turtle")
	if err == nil {
		t.Fatal("expected error for disallowed content type, got nil")
	}
	if !errors.Is(err, ErrRDFContentTypeNotSupported) {
		t.Errorf("expected ErrRDFContentTypeNotSupported, got %v", err)
	}
}

// TestRDFTermType tests term type constants
func TestRDFTermType(t *testing.T) {
	if RDFTermTypeIRI != "IRI" {
		t.Errorf("expected RDFTermTypeIRI to be 'IRI', got %q", RDFTermTypeIRI)
	}
	if RDFTermTypeLiteral != "Literal" {
		t.Errorf("expected RDFTermTypeLiteral to be 'Literal', got %q", RDFTermTypeLiteral)
	}
	if RDFTermTypeBlankNode != "BlankNode" {
		t.Errorf("expected RDFTermTypeBlankNode to be 'BlankNode', got %q", RDFTermTypeBlankNode)
	}
}
