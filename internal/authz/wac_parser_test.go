// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// mockWACRDFParser is a mock RDF parser that returns WAC-like triples
type mockWACRDFParser struct {
	triples    []RDFTriple
	parseFunc  func(ctx context.Context, content []byte, contentType string) (RDFParseResult, error)
	parseError error
}

func (m *mockWACRDFParser) Parse(ctx context.Context, content []byte, contentType string) (RDFParseResult, error) {
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

func (m *mockWACRDFParser) SupportedContentTypes() []string {
	return []string{"text/turtle", "application/ld+json"}
}

// createTestRDFRegistry creates a test RDF parser registry with mock parsers
func createTestRDFRegistry(mockParser RDFParser) *RDFParserRegistry {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	registry.Register(mockParser)
	return registry
}

// createTestWACParser creates a test WAC parser with a mock RDF parser
func createTestWACParser(mockRDFParser RDFParser) *WACParser {
	registry := createTestRDFRegistry(mockRDFParser)
	parser, _ := NewWACParser(DefaultWACParserOptions(), registry)
	return parser
}

// TestWACParserCreation tests creating a WAC parser
func TestWACParserCreation(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	parser, err := NewWACParser(DefaultWACParserOptions(), registry)
	if err != nil {
		t.Fatalf("failed to create WAC parser: %v", err)
	}
	if parser == nil {
		t.Fatal("WAC parser is nil")
	}
}

// TestWACParserNilRDFParser tests error handling for nil RDF parser
func TestWACParserNilRDFParser(t *testing.T) {
	_, err := NewWACParser(DefaultWACParserOptions(), nil)
	if err == nil {
		t.Fatal("expected error for nil RDF parser, got nil")
	}
}

// TestWACParserDefaultOptions tests default options
func TestWACParserDefaultOptions(t *testing.T) {
	options := DefaultWACParserOptions()

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

// TestWACParserSupportedContentTypes tests supported content types
func TestWACParserSupportedContentTypes(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	parser, _ := NewWACParser(DefaultWACParserOptions(), registry)

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

// TestWACParserParseBasicACL tests parsing a basic ACL document
func TestWACParserParseBasicACL(t *testing.T) {
	// Create mock RDF triples for a basic ACL
	triples := []RDFTriple{
		// Authorization resource
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/ns/auth/acl#Authorization", ObjectType: RDFTermTypeIRI},
		// accessTo
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/auth/acl#accessTo", Object: "https://example.org/resource", ObjectType: RDFTermTypeIRI},
		// agent
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/auth/acl#agent", Object: "https://example.org/alice#webid", ObjectType: RDFTermTypeIRI},
		// mode
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/auth/acl#mode", Object: "http://www.w3.org/ns/auth/acl#Read", ObjectType: RDFTermTypeIRI},
	}

	mockParser := &mockWACRDFParser{triples: triples}
	wacParser := createTestWACParser(mockParser)

	result, err := wacParser.Parse(context.Background(), []byte("test content"), "text/turtle")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Should have parsed the triples
	if len(result.Triples) != 4 {
		t.Errorf("expected 4 triples, got %d", len(result.Triples))
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

// TestWACParserParseWithInputTooLarge tests error for input that's too large
func TestWACParserParseWithInputTooLarge(t *testing.T) {
	mockParser := &mockWACRDFParser{triples: []RDFTriple{}}
	wacParser := createTestWACParser(mockParser)

	// Create content larger than the absolute limit
	largeContent := make([]byte, maxRDFInputSize+1)
	for i := range largeContent {
		largeContent[i] = 'a'
	}

	_, err := wacParser.Parse(context.Background(), largeContent, "text/turtle")
	if err == nil {
		t.Fatal("expected error for input too large, got nil")
	}
}

// TestWACParserParseWithRDFParserError tests error handling when RDF parser fails
func TestWACParserParseWithRDFParserError(t *testing.T) {
	mockParser := &mockWACRDFParser{
		parseError: errors.New("RDF parser error"),
	}
	wacParser := createTestWACParser(mockParser)

	_, err := wacParser.Parse(context.Background(), []byte("test"), "text/turtle")
	if err == nil {
		t.Fatal("expected error from RDF parser, got nil")
	}
	if !errors.Is(err, ErrWACParseFailed) {
		t.Errorf("expected ErrWACParseFailed, got %v", err)
	}
}

// TestWACParserTimeout tests timeout handling
func TestWACParserTimeout(t *testing.T) {
	options := DefaultWACParserOptions()
	options.Timeout = 1 * time.Nanosecond // Very short timeout

	// Create a slow mock RDF parser
	mockParser := &mockWACRDFParser{
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

	wacParser, _ := NewWACParser(options, registry)

	_, err := wacParser.Parse(context.Background(), []byte("test"), "text/turtle")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// TestWACParserExtractRules tests WAC rule extraction
func TestWACParserExtractRules(t *testing.T) {
	// Create a more complete set of triples for WAC
	triples := []RDFTriple{
		// Authorization 1
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/ns/auth/acl#Authorization", ObjectType: RDFTermTypeIRI},
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/auth/acl#accessTo", Object: "https://example.org/resource", ObjectType: RDFTermTypeIRI},
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/auth/acl#agent", Object: "https://example.org/alice#webid", ObjectType: RDFTermTypeIRI},
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/auth/acl#mode", Object: "http://www.w3.org/ns/auth/acl#Read", ObjectType: RDFTermTypeIRI},
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/auth/acl#mode", Object: "http://www.w3.org/ns/auth/acl#Write", ObjectType: RDFTermTypeIRI},
	}

	mockParser := &mockWACRDFParser{triples: triples}
	wacParser := createTestWACParser(mockParser)

	// Call the internal method directly for testing
	rules, err := wacParser.extractWACRulesFromTriples(context.Background(), triples)
	if err != nil {
		t.Fatalf("rule extraction failed: %v", err)
	}

	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}

	if len(rules) > 0 {
		rule := rules[0]
		if rule.Authorization != "https://example.org/resource.acl" {
			t.Errorf("expected authorization %q, got %q", "https://example.org/resource.acl", rule.Authorization)
		}
		if rule.AccessTo != "https://example.org/resource" {
			t.Errorf("expected accessTo %q, got %q", "https://example.org/resource", rule.AccessTo)
		}
		if rule.Agent != "https://example.org/alice#webid" {
			t.Errorf("expected agent %q, got %q", "https://example.org/alice#webid", rule.Agent)
		}
		if len(rule.Modes) != 2 {
			t.Errorf("expected 2 modes, got %d", len(rule.Modes))
		}
	}
}

// TestWACParserParseAccessMode tests access mode parsing
func TestWACParserParseAccessMode(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	wacParser, _ := NewWACParser(DefaultWACParserOptions(), registry)

	testCases := []struct {
		input    string
		expected AccessMode
	}{
		{"http://www.w3.org/ns/auth/acl#Read", AccessModeRead},
		{"http://www.w3.org/ns/auth/acl#Write", AccessModeWrite},
		{"http://www.w3.org/ns/auth/acl#Append", AccessModeAppend},
		{"http://www.w3.org/ns/auth/acl#Control", AccessModeControl},
		{"acl:Read", AccessModeRead},
		{"acl:Write", AccessModeWrite},
		{"Read", AccessModeRead},
		{"Write", AccessModeWrite},
		{"<http://www.w3.org/ns/auth/acl#Read>", AccessModeRead},
		{"unknown", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := wacParser.parseAccessMode(tc.input)
			if result != tc.expected {
				t.Errorf("parseAccessMode(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

// TestWACParserValidateRule tests rule validation
func TestWACParserValidateRule(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	wacParser, _ := NewWACParser(DefaultWACParserOptions(), registry)

	testCases := []struct {
		name    string
		rule    WACRule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: WACRule{
				Authorization: "https://example.org/resource.acl",
				AccessTo:      "https://example.org/resource",
				Agent:         "https://example.org/alice",
				Modes:         []AccessMode{AccessModeRead},
			},
			wantErr: false,
		},
		{
			name: "missing authorization",
			rule: WACRule{
				AccessTo: "https://example.org/resource",
				Agent:    "https://example.org/alice",
				Modes:    []AccessMode{AccessModeRead},
			},
			wantErr: true,
		},
		{
			name: "missing accessTo",
			rule: WACRule{
				Authorization: "https://example.org/resource.acl",
				Agent:         "https://example.org/alice",
				Modes:         []AccessMode{AccessModeRead},
			},
			wantErr: true,
		},
		{
			name: "missing agent and agentClass",
			rule: WACRule{
				Authorization: "https://example.org/resource.acl",
				AccessTo:      "https://example.org/resource",
				Modes:         []AccessMode{AccessModeRead},
			},
			wantErr: true,
		},
		{
			name: "missing modes",
			rule: WACRule{
				Authorization: "https://example.org/resource.acl",
				AccessTo:      "https://example.org/resource",
				Agent:         "https://example.org/alice",
			},
			wantErr: true,
		},
		{
			name: "invalid authorization URI",
			rule: WACRule{
				Authorization: "invalid-uri",
				AccessTo:      "https://example.org/resource",
				Agent:         "https://example.org/alice",
				Modes:         []AccessMode{AccessModeRead},
			},
			wantErr: true,
		},
		{
			name: "invalid accessTo URI",
			rule: WACRule{
				Authorization: "https://example.org/resource.acl",
				AccessTo:      "invalid-uri",
				Agent:         "https://example.org/alice",
				Modes:         []AccessMode{AccessModeRead},
			},
			wantErr: true,
		},
		{
			name: "valid rule with agentClass",
			rule: WACRule{
				Authorization: "https://example.org/resource.acl",
				AccessTo:      "https://example.org/resource",
				AgentClass:    "http://xmlns.com/foaf/0.1/Agent",
				Modes:         []AccessMode{AccessModeRead},
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := wacParser.validateWACRule(tc.rule)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateWACRule() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestWACParserFindAuthorizationURIs tests finding authorization URIs
func TestWACParserFindAuthorizationURIs(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	wacParser, _ := NewWACParser(DefaultWACParserOptions(), registry)

	triples := []RDFTriple{
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/ns/auth/acl#Authorization", ObjectType: RDFTermTypeIRI},
		{Subject: "https://example.org/other.acl", Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/ns/auth/acl#Authorization", ObjectType: RDFTermTypeIRI},
		{Subject: "https://example.org/resource", Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/2000/01/rdf-schema#Resource", ObjectType: RDFTermTypeIRI},
	}

	authURIs := wacParser.findAuthorizationURIs(triples)

	if len(authURIs) != 2 {
		t.Errorf("expected 2 authorization URIs, got %d", len(authURIs))
	}

	// Check that non-authorization types are not included
	for _, uri := range authURIs {
		if uri == "https://example.org/resource" {
			t.Error("non-authorization URI included in results")
		}
	}
}

// TestWACParserFindTriplesForSubject tests finding triples for a subject
func TestWACParserFindTriplesForSubject(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	wacParser, _ := NewWACParser(DefaultWACParserOptions(), registry)

	triples := []RDFTriple{
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/ns/auth/acl#Authorization", ObjectType: RDFTermTypeIRI},
		{Subject: "https://example.org/resource.acl", Predicate: "http://www.w3.org/ns/auth/acl#accessTo", Object: "https://example.org/resource", ObjectType: RDFTermTypeIRI},
		{Subject: "https://example.org/other.acl", Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/ns/auth/acl#Authorization", ObjectType: RDFTermTypeIRI},
	}

	result := wacParser.findTriplesForSubject(triples, "https://example.org/resource.acl")

	if len(result) != 2 {
		t.Errorf("expected 2 triples for subject, got %d", len(result))
	}

	for _, triple := range result {
		if triple.Subject != "https://example.org/resource.acl" {
			t.Errorf("expected subject %q, got %q", "https://example.org/resource.acl", triple.Subject)
		}
	}
}

// TestWACParserMaxRules tests the maximum rules limit
func TestWACParserMaxRules(t *testing.T) {
	options := DefaultWACParserOptions()
	options.MaxRules = 2 // Very small limit

	// Create many rules
	triples := make([]RDFTriple, 0)
	for i := 0; i < 5; i++ {
		authURI := fmt.Sprintf("https://example.org/resource%d.acl", i)
		resourceURI := fmt.Sprintf("https://example.org/resource%d", i)
		agentURI := fmt.Sprintf("https://example.org/agent%d", i)

		triples = append(triples,
			RDFTriple{Subject: authURI, Predicate: "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", Object: "http://www.w3.org/ns/auth/acl#Authorization", ObjectType: RDFTermTypeIRI},
			RDFTriple{Subject: authURI, Predicate: "http://www.w3.org/ns/auth/acl#accessTo", Object: resourceURI, ObjectType: RDFTermTypeIRI},
			RDFTriple{Subject: authURI, Predicate: "http://www.w3.org/ns/auth/acl#agent", Object: agentURI, ObjectType: RDFTermTypeIRI},
			RDFTriple{Subject: authURI, Predicate: "http://www.w3.org/ns/auth/acl#mode", Object: "http://www.w3.org/ns/auth/acl#Read", ObjectType: RDFTermTypeIRI},
		)
	}

	mockParser := &mockWACRDFParser{triples: triples}
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	registry.Register(mockParser)

	wacParser, _ := NewWACParser(options, registry)

	_, err := wacParser.Parse(context.Background(), []byte("test"), "text/turtle")
	if err == nil {
		t.Fatal("expected error for too many rules, got nil")
	}
	if !errors.Is(err, ErrWACParseFailed) {
		t.Errorf("expected ErrWACParseFailed, got %v", err)
	}
}

// TestWACPolicyStruct tests the WACPolicy struct
func TestWACPolicyStruct(t *testing.T) {
	policy := WACPolicy{
		ResourceURI:      "https://example.org/resource",
		AuthorizationURI: "https://example.org/resource.acl",
		Rules: []WACRule{
			{
				Authorization: "https://example.org/resource.acl",
				AccessTo:      "https://example.org/resource",
				Agent:         "https://example.org/alice",
				Modes:         []AccessMode{AccessModeRead, AccessModeWrite},
			},
		},
		Owner: "https://example.org/alice",
	}

	if policy.ResourceURI != "https://example.org/resource" {
		t.Errorf("expected resource URI %q, got %q", "https://example.org/resource", policy.ResourceURI)
	}
	if policy.AuthorizationURI != "https://example.org/resource.acl" {
		t.Errorf("expected authorization URI %q, got %q", "https://example.org/resource.acl", policy.AuthorizationURI)
	}
	if len(policy.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(policy.Rules))
	}
	if policy.Owner != "https://example.org/alice" {
		t.Errorf("expected owner %q, got %q", "https://example.org/alice", policy.Owner)
	}
}

// TestWACRuleStruct tests the WACRule struct
func TestWACRuleStruct(t *testing.T) {
	rule := WACRule{
		Authorization: "https://example.org/resource.acl",
		AccessTo:      "https://example.org/resource",
		Agent:         "https://example.org/alice",
		AgentClass:    "http://xmlns.com/foaf/0.1/Agent",
		Modes:         []AccessMode{AccessModeRead, AccessModeWrite, AccessModeControl},
		DefaultAccess: true,
		Origin:        "https://example.org",
	}

	if rule.Authorization != "https://example.org/resource.acl" {
		t.Errorf("expected authorization %q, got %q", "https://example.org/resource.acl", rule.Authorization)
	}
	if rule.AccessTo != "https://example.org/resource" {
		t.Errorf("expected accessTo %q, got %q", "https://example.org/resource", rule.AccessTo)
	}
	if rule.Agent != "https://example.org/alice" {
		t.Errorf("expected agent %q, got %q", "https://example.org/alice", rule.Agent)
	}
	if rule.AgentClass != "http://xmlns.com/foaf/0.1/Agent" {
		t.Errorf("expected agentClass %q, got %q", "http://xmlns.com/foaf/0.1/Agent", rule.AgentClass)
	}
	if len(rule.Modes) != 3 {
		t.Errorf("expected 3 modes, got %d", len(rule.Modes))
	}
	if !rule.DefaultAccess {
		t.Error("expected defaultAccess to be true")
	}
	if rule.Origin != "https://example.org" {
		t.Errorf("expected origin %q, got %q", "https://example.org", rule.Origin)
	}
}

// TestWACParserInterfaceCompliance tests that WACParser implements RDFParser
func TestWACParserInterfaceCompliance(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	parser, _ := NewWACParser(DefaultWACParserOptions(), registry)

	// This should compile if the interface is properly implemented
	var _ RDFParser = parser
}

// TestWACParserEmptyContent tests parsing empty content
func TestWACParserEmptyContent(t *testing.T) {
	mockParser := &mockWACRDFParser{triples: []RDFTriple{}}
	wacParser := createTestWACParser(mockParser)

	result, err := wacParser.Parse(context.Background(), []byte(""), "text/turtle")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Should handle empty content gracefully
	if result.ContentType != "text/turtle" {
		t.Errorf("expected content type text/turtle, got %q", result.ContentType)
	}
}

// TestWACParserEnforcementModeShadow tests WAC parser in shadow mode
func TestWACParserEnforcementModeShadow(t *testing.T) {
	t.Parallel()

	// Create RDF parser registry with mock parser
	mockParser := &mockWACRDFParser{}
	registry := createTestRDFRegistry(mockParser)

	// Test shadow mode (default)
	options := DefaultWACParserOptions()
	parser, err := NewWACParser(options, registry)
	if err != nil {
		t.Fatalf("Failed to create WAC parser: %v", err)
	}
	if parser.IsEnforcementModeEnabled() {
		t.Error("Default should be shadow mode")
	}
}

// TestWACParserEnforcementModeEnabled tests WAC parser in enforcement mode
func TestWACParserEnforcementModeEnabled(t *testing.T) {
	t.Parallel()

	// Create RDF parser registry with mock parser
	mockParser := &mockWACRDFParser{}
	registry := createTestRDFRegistry(mockParser)

	// Test enforcement mode
	options := DefaultWACParserOptions()
	options.EnforcementMode = true
	parser, err := NewWACParser(options, registry)
	if err != nil {
		t.Fatalf("Failed to create WAC parser: %v", err)
	}
	if !parser.IsEnforcementModeEnabled() {
		t.Error("Should be enforcement mode when configured")
	}
}
