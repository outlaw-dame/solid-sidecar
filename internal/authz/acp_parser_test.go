// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockACPParser is a mock RDF parser for ACP testing
type mockACPParser struct {
	triples    []RDFTriple
	parseFunc  func(ctx context.Context, content []byte, contentType string) (RDFParseResult, error)
	parseError error
}

func (m *mockACPParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
	if m.parseFunc != nil {
		return m.parseFunc(ctx, content, contentType)
	}
	if m.parseError != nil {
		return RDFParseResult{}, m.parseError
	}
	return RDFParseResult{
		Triples:     m.triples,
		ContentType: contentType,
		SHA256:      "test-hash",
	}, nil
}

func (m *mockACPParser) SupportedContentTypes() []string {
	return []string{"text/turtle", "application/ld+json"}
}

// createTestACPRegistry creates a test RDF parser registry for ACP
func createTestACPRegistry(mockParser RDFParser) *RDFParserRegistry {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	registry.Register(mockParser)
	return registry
}

// createTestACPParser creates a test ACP parser with a mock RDF parser
func createTestACPParser(mockRDFParser RDFParser) *ACPParser {
	registry := createTestACPRegistry(mockRDFParser)
	parser, _ := NewACPParser(DefaultACPParserOptions(), registry)
	return parser
}

// TestACPParserCreation tests creating an ACP parser
func TestACPParserCreation(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	parser, err := NewACPParser(DefaultACPParserOptions(), registry)
	if err != nil {
		t.Fatalf("failed to create ACP parser: %v", err)
	}
	if parser == nil {
		t.Fatal("ACP parser is nil")
	}
}

// TestACPParserNilRDFParser tests error handling for nil RDF parser
func TestACPParserNilRDFParser(t *testing.T) {
	_, err := NewACPParser(DefaultACPParserOptions(), nil)
	if err == nil {
		t.Fatal("expected error for nil RDF parser, got nil")
	}
}

// TestACPParserDefaultOptions tests default options
func TestACPParserDefaultOptions(t *testing.T) {
	options := DefaultACPParserOptions()

	if options.MaxRules != 100 {
		t.Errorf("expected default max rules 100, got %d", options.MaxRules)
	}
	if options.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", options.Timeout)
	}
	if options.Logger != nil {
		t.Error("expected logger to be nil by default")
	}
}

// TestACPParserSupportedContentTypes tests supported content types
func TestACPParserSupportedContentTypes(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	parser, _ := NewACPParser(DefaultACPParserOptions(), registry)

	supported := parser.SupportedContentTypes()
	if len(supported) == 0 {
		t.Fatal("expected supported content types, got empty")
	}

	// Should support common RDF content types
	expectedTypes := []string{"text/turtle", "application/ld+json", "application/n-triples"}
	for _, expected := range expectedTypes {
		found := false
		for _, actual := range supported {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected supported content type %q, not found", expected)
		}
	}
}

// TestACPParserParseBasicACL tests parsing a basic ACP document
func TestACPParserParseBasicACL(t *testing.T) {
	// Create mock RDF triples for a basic ACP policy
	triples := []RDFTriple{
		// Policy resource
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/ns/solid/acp#Policy", ObjectType: RDFTermTypeIRI},
		// appliesTo
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/solid/acp#appliesTo", Object: "https://example.org/resource", ObjectType: RDFTermTypeIRI},
		// allow
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/solid/acp#allow", Object: "_:access1", ObjectType: RDFTermTypeBlankNode},
		// access resource
		{Subject: "_:access1", Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/ns/solid/acp#Access", ObjectType: RDFTermTypeIRI},
		{Subject: "_:access1", Predicate: "http://www.w3.org/ns/solid/acp#accessTo", Object: "https://example.org/resource", ObjectType: RDFTermTypeIRI},
		{Subject: "_:access1", Predicate: "http://www.w3.org/ns/solid/acp#agent", Object: "https://example.org/alice#webid", ObjectType: RDFTermTypeIRI},
		{Subject: "_:access1", Predicate: "http://www.w3.org/ns/solid/acp#mode", Object: "http://www.w3.org/ns/solid/acp#Read", ObjectType: RDFTermTypeIRI},
	}

	mockParser := &mockACPParser{triples: triples}
	acpParser := createTestACPParser(mockParser)

	// Note: The current implementation doesn't fully parse blank nodes,
	// so this test will exercise the parsing but may not extract all rules
	result, err := acpParser.Parse(context.Background(), []byte("test content"), "text/turtle")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Should have parsed the triples
	if len(result.Triples) != len(triples) {
		t.Errorf("expected %d triples, got %d", len(triples), len(result.Triples))
	}

	// Should have content hash
	if result.SHA256 == "" {
		t.Error("expected content hash, got empty")
	}

	// Should have content type
	if result.ContentType != "text/turtle" {
		t.Errorf("expected content type text/turtle, got %q", result.ContentType)
	}
}

// TestACPParserInterfaceCompliance tests that ACPParser implements RDFParser
func TestACPParserInterfaceCompliance(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	parser, _ := NewACPParser(DefaultACPParserOptions(), registry)

	// This should compile if the interface is properly implemented
	var _ RDFParser = parser
}

// TestACPParserWithInputTooLarge tests error for input that's too large
func TestACPParserWithInputTooLarge(t *testing.T) {
	mockParser := &mockACPParser{triples: []RDFTriple{}}
	acpParser := createTestACPParser(mockParser)

	// Create content larger than the absolute limit
	largeContent := make([]byte, maxRDFInputSize+1)
	for i := range largeContent {
		largeContent[i] = 'a'
	}

	_, err := acpParser.Parse(context.Background(), largeContent, "text/turtle")
	if err == nil {
		t.Fatal("expected error for input too large, got nil")
	}
}

// TestACPParserTimeout tests timeout handling
func TestACPParserTimeout(t *testing.T) {
	options := DefaultACPParserOptions()
	options.Timeout = 1 * time.Nanosecond // Very short timeout

	// Create a slow mock RDF parser
	mockParser := &mockACPParser{
		parseFunc: func(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
			select {
			case <-ctx.Done():
				return RDFParseResult{}, ctx.Err()
			case <-time.After(10 * time.Millisecond):
				return RDFParseResult{}, nil
			}
		},
	}

	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	registry.Register(mockParser)

	acpParser, _ := NewACPParser(options, registry)

	_, err := acpParser.Parse(context.Background(), []byte("test"), "text/turtle")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// TestACPPolicyStruct tests the ACPPolicy struct
func TestACPPolicyStruct(t *testing.T) {
	policy := ACPPolicy{
		ResourceURI: "https://example.org/resource",
		PolicyURI:   "https://example.org/resource.acl",
		Rules: []ACPRule{
			{
				Access: ACPAccess{
					AccessTo: "https://example.org/resource",
					Allows:   true,
					Agent:    "https://example.org/alice",
					Modes:    []AccessMode{AccessModeRead, AccessModeWrite},
				},
				Resource: "https://example.org/resource",
				Policy:   "https://example.org/resource.acl",
			},
		},
		Owner:   "https://example.org/alice",
		Inherit: true,
	}

	if policy.ResourceURI != "https://example.org/resource" {
		t.Errorf("expected resource URI %q, got %q", "https://example.org/resource", policy.ResourceURI)
	}
	if policy.PolicyURI != "https://example.org/resource.acl" {
		t.Errorf("expected policy URI %q, got %q", "https://example.org/resource.acl", policy.PolicyURI)
	}
	if len(policy.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(policy.Rules))
	}
	if policy.Owner != "https://example.org/alice" {
		t.Errorf("expected owner %q, got %q", "https://example.org/alice", policy.Owner)
	}
	if !policy.Inherit {
		t.Error("expected inherit to be true")
	}
}

// TestACPRuleStruct tests the ACPRule struct
func TestACPRuleStruct(t *testing.T) {
	rule := ACPRule{
		Access: ACPAccess{
			AccessTo:   "https://example.org/resource",
			Allows:     true,
			Agent:      "https://example.org/alice",
			AgentClass: "http://xmlns.com/foaf/0.1/Agent",
			Modes:      []AccessMode{AccessModeRead, AccessModeWrite, AccessModeControl},
			Origin:     "https://example.org",
			Inherit:    true,
		},
		Resource: "https://example.org/resource",
		Policy:   "https://example.org/resource.acl",
	}

	if rule.Access.AccessTo != "https://example.org/resource" {
		t.Errorf("expected accessTo %q, got %q", "https://example.org/resource", rule.Access.AccessTo)
	}
	if !rule.Access.Allows {
		t.Error("expected allows to be true")
	}
	if rule.Access.Agent != "https://example.org/alice" {
		t.Errorf("expected agent %q, got %q", "https://example.org/alice", rule.Access.Agent)
	}
	if rule.Access.AgentClass != "http://xmlns.com/foaf/0.1/Agent" {
		t.Errorf("expected agentClass %q, got %q", "http://xmlns.com/foaf/0.1/Agent", rule.Access.AgentClass)
	}
	if len(rule.Access.Modes) != 3 {
		t.Errorf("expected 3 modes, got %d", len(rule.Access.Modes))
	}
	if !rule.Access.Inherit {
		t.Error("expected inherit to be true")
	}
	if rule.Resource != "https://example.org/resource" {
		t.Errorf("expected resource %q, got %q", "https://example.org/resource", rule.Resource)
	}
	if rule.Policy != "https://example.org/resource.acl" {
		t.Errorf("expected policy %q, got %q", "https://example.org/resource.acl", rule.Policy)
	}
}

// TestACPParserEmptyContent tests parsing empty content
func TestACPParserEmptyContent(t *testing.T) {
	mockParser := &mockACPParser{triples: []RDFTriple{}}
	acpParser := createTestACPParser(mockParser)

	result, err := acpParser.Parse(context.Background(), []byte(""), "text/turtle")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Should handle empty content gracefully
	if result.ContentType != "text/turtle" {
		t.Errorf("expected content type text/turtle, got %q", result.ContentType)
	}
}

// TestACPParserParseAccessMode tests access mode parsing for ACP
func TestACPParserParseAccessMode(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	acpParser, _ := NewACPParser(DefaultACPParserOptions(), registry)

	testCases := []struct {
		input    string
		expected AccessMode
	}{
		{"http://www.w3.org/ns/solid/acp#Read", AccessModeRead},
		{"http://www.w3.org/ns/solid/acp#Write", AccessModeWrite},
		{"http://www.w3.org/ns/solid/acp#Append", AccessModeAppend},
		{"http://www.w3.org/ns/solid/acp#Control", AccessModeControl},
		{"acp:Read", AccessModeRead},
		{"Read", AccessModeRead},
		{"<http://www.w3.org/ns/solid/acp#Read>", AccessModeRead},
		{"unknown", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := acpParser.parseAccessMode(tc.input)
			if result != tc.expected {
				t.Errorf("parseAccessMode(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

// Ensure errors import is used
var _ = errors.New("test error")

// TestACPParserEnforcementModeShadow tests ACP parser in shadow mode
func TestACPParserEnforcementModeShadow(t *testing.T) {
	t.Parallel()

	// Create RDF parser registry with mock parser
	mockParser := &mockACPParser{}
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	registry.Register(mockParser)

	// Test shadow mode (default)
	options := DefaultACPParserOptions()
	parser, err := NewACPParser(options, registry)
	if err != nil {
		t.Fatalf("Failed to create ACP parser: %v", err)
	}
	if parser.IsEnforcementModeEnabled() {
		t.Error("Default should be shadow mode")
	}
}

// TestACPParserEnforcementModeEnabled tests ACP parser in enforcement mode
func TestACPParserEnforcementModeEnabled(t *testing.T) {
	t.Parallel()

	// Create RDF parser registry with mock parser
	mockParser := &mockACPParser{}
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	registry.Register(mockParser)

	// Test enforcement mode
	options := DefaultACPParserOptions()
	options.EnforcementMode = true
	parser, err := NewACPParser(options, registry)
	if err != nil {
		t.Fatalf("Failed to create ACP parser: %v", err)
	}
	if !parser.IsEnforcementModeEnabled() {
		t.Error("Should be enforcement mode when configured")
	}
}
