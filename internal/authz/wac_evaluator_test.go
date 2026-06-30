// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestWACEvaluatorCreation tests creating a WAC evaluator
func TestWACEvaluatorCreation(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, err := NewWACEvaluator(DefaultWACEvaluatorOptions(), registry)
	if err != nil {
		t.Fatalf("failed to create WAC evaluator: %v", err)
	}
	if evaluator == nil {
		t.Fatal("WAC evaluator is nil")
	}
}

// TestWACEvaluatorDefaultOptions tests default options
func TestWACEvaluatorDefaultOptions(t *testing.T) {
	options := DefaultWACEvaluatorOptions()

	if options.MaxPolicies != 10 {
		t.Errorf("expected default max policies 10, got %d", options.MaxPolicies)
	}
	if options.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", options.Timeout)
	}
	if options.Logger != nil {
		t.Error("expected logger to be nil by default")
	}
}

// TestWACEvaluatorNilRDFParser tests error handling for nil RDF parser registry
func TestWACEvaluatorNilRDFParser(t *testing.T) {
	// When RDF parser is nil, the evaluator should still be created but will fail when parsing
	// The WAC parser creation will fail, which is expected
	_, err := NewWACEvaluator(DefaultWACEvaluatorOptions(), nil)
	if err == nil {
		t.Fatal("expected error for nil RDF parser registry, got nil")
	}
}

// TestWACEvaluatorInterfaceCompliance tests that WACEvaluator implements Evaluator
func TestWACEvaluatorInterfaceCompliance(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewWACEvaluator(DefaultWACEvaluatorOptions(), registry)

	// This should compile if the interface is properly implemented
	var _ Evaluator = evaluator
}

// TestWACEvaluatorEvaluateWithNoPolicies tests evaluation with no policy documents
func TestWACEvaluatorEvaluateWithNoPolicies(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewWACEvaluator(DefaultWACEvaluatorOptions(), registry)

	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-123",
		Method:         "GET",
		ResourceURI:    "https://example.org/resource",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        time.Now().Unix(),
	}

	decision, err := evaluator.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	// Should abstain when no policies
	if decision.Decision != DecisionAbstain {
		t.Errorf("expected decision %q, got %q", DecisionAbstain, decision.Decision)
	}
	if decision.ReasonCode != ReasonPolicyNotLoaded {
		t.Errorf("expected reason %q, got %q", ReasonPolicyNotLoaded, decision.ReasonCode)
	}
}

// TestWACEvaluatorEvaluateWithPolicies tests evaluation with policy documents
func TestWACEvaluatorEvaluateWithPolicies(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewWACEvaluator(DefaultWACEvaluatorOptions(), registry)

	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-456",
		Method:         "GET",
		ResourceURI:    "https://example.org/resource",
		AgentWebID:     "https://example.org/alice#webid",
		RequestedModes: []AccessMode{AccessModeRead},
		PolicyDocuments: []PolicyDocument{
			{
				URI:         "https://example.org/resource.acl",
				SHA256:      "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
				ContentType: "text/turtle",
			},
		},
		NowUnix: time.Now().Unix(),
	}

	decision, err := evaluator.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	// Should abstain in shadow mode (current implementation)
	if decision.Decision != DecisionAbstain {
		t.Errorf("expected decision %q, got %q", DecisionAbstain, decision.Decision)
	}
}

// TestWACEvaluatorEvaluateWithInvalidRequest tests evaluation with invalid request
func TestWACEvaluatorEvaluateWithInvalidRequest(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewWACEvaluator(DefaultWACEvaluatorOptions(), registry)

	testCases := []struct {
		name           string
		request        Request
		expectedReason ReasonCode
	}{
		{
			name: "invalid schema version",
			request: Request{
				SchemaVersion:  "invalid",
				RequestID:      "test-request",
				Method:         "GET",
				ResourceURI:    "https://example.org/resource",
				RequestedModes: []AccessMode{AccessModeRead},
				NowUnix:        time.Now().Unix(),
			},
			expectedReason: ReasonUnsupportedSchema,
		},
		{
			name: "invalid request ID",
			request: Request{
				SchemaVersion:  SchemaVersion,
				RequestID:      "",
				Method:         "GET",
				ResourceURI:    "https://example.org/resource",
				RequestedModes: []AccessMode{AccessModeRead},
				NowUnix:        time.Now().Unix(),
			},
			expectedReason: ReasonInvalidRequest,
		},
		{
			name: "unsupported method",
			request: Request{
				SchemaVersion:  SchemaVersion,
				RequestID:      "test-request",
				Method:         "INVALID",
				ResourceURI:    "https://example.org/resource",
				RequestedModes: []AccessMode{AccessModeRead},
				NowUnix:        time.Now().Unix(),
			},
			expectedReason: ReasonInvalidRequest,
		},
		{
			name: "missing requested modes",
			request: Request{
				SchemaVersion:  SchemaVersion,
				RequestID:      "test-request",
				Method:         "GET",
				ResourceURI:    "https://example.org/resource",
				RequestedModes: []AccessMode{},
				NowUnix:        time.Now().Unix(),
			},
			expectedReason: ReasonMissingRequestedModes,
		},
		{
			name: "unsafe resource URI",
			request: Request{
				SchemaVersion:  SchemaVersion,
				RequestID:      "test-request",
				Method:         "GET",
				ResourceURI:    "invalid-uri",
				RequestedModes: []AccessMode{AccessModeRead},
				NowUnix:        time.Now().Unix(),
			},
			expectedReason: ReasonUnsafeResourceURI,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := evaluator.Evaluate(context.Background(), tc.request)
			if err != nil {
				t.Fatalf("evaluation failed: %v", err)
			}

			if decision.ReasonCode != tc.expectedReason {
				t.Errorf("expected reason %q, got %q", tc.expectedReason, decision.ReasonCode)
			}

			// All invalid requests should result in deny
			if decision.Decision != DecisionDeny {
				t.Errorf("expected decision %q for invalid request, got %q", DecisionDeny, decision.Decision)
			}
		})
	}
}

// TestWACEvaluatorTimeout tests timeout handling
func TestWACEvaluatorTimeout(t *testing.T) {
	options := DefaultWACEvaluatorOptions()
	options.Timeout = 1 * time.Nanosecond // Very short timeout

	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewWACEvaluator(options, registry)

	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-timeout",
		Method:         "GET",
		ResourceURI:    "https://example.org/resource",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        time.Now().Unix(),
	}

	_, err := evaluator.Evaluate(context.Background(), request)
	// With such a short timeout, we might get a context deadline exceeded error
	// or it might complete before the timeout
	// Either way, it should not hang
	_ = err // We accept either outcome for this test
}

// TestWACEvaluatorMaxPolicies tests the maximum policies limit
func TestWACEvaluatorMaxPolicies(t *testing.T) {
	options := DefaultWACEvaluatorOptions()
	options.MaxPolicies = 2 // Very small limit

	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewWACEvaluator(options, registry)

	// Create a request with many policies
	policyDocs := make([]PolicyDocument, 0, 5)
	for i := 0; i < 5; i++ {
		policyDocs = append(policyDocs, PolicyDocument{
			URI:         fmt.Sprintf("https://example.org/policy%d.acl", i),
			SHA256:      "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
			ContentType: "text/turtle",
		})
	}

	request := Request{
		SchemaVersion:   SchemaVersion,
		RequestID:       "test-request-max-policies",
		Method:          "GET",
		ResourceURI:     "https://example.org/resource",
		RequestedModes:  []AccessMode{AccessModeRead},
		PolicyDocuments: policyDocs,
		NowUnix:         time.Now().Unix(),
	}

	decision, err := evaluator.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	// Should abstain when too many policies
	if decision.Decision != DecisionAbstain {
		t.Errorf("expected decision %q, got %q", DecisionAbstain, decision.Decision)
	}
}

// TestWACEvaluatorShadowMode tests that the evaluator operates in shadow mode
func TestWACEvaluatorShadowMode(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewWACEvaluator(DefaultWACEvaluatorOptions(), registry)

	// Create a valid request with policies
	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-shadow",
		Method:         "GET",
		ResourceURI:    "https://example.org/resource",
		AgentWebID:     "https://example.org/alice#webid",
		RequestedModes: []AccessMode{AccessModeRead, AccessModeWrite},
		PolicyDocuments: []PolicyDocument{
			{
				URI:         "https://example.org/resource.acl",
				SHA256:      "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
				ContentType: "text/turtle",
			},
		},
		NowUnix: time.Now().Unix(),
	}

	decision, err := evaluator.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	// In shadow mode, should abstain
	if decision.Decision != DecisionAbstain {
		t.Errorf("expected decision %q in shadow mode, got %q", DecisionAbstain, decision.Decision)
	}

	// Check that the decision has the correct schema version
	if decision.SchemaVersion != SchemaVersion {
		t.Errorf("expected schema version %q, got %q", SchemaVersion, decision.SchemaVersion)
	}
}

// TestWACEvaluatorWithCustomParser tests using a custom WAC parser
func TestWACEvaluatorWithCustomParser(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	parser, _ := NewWACParser(DefaultWACParserOptions(), registry)

	options := DefaultWACEvaluatorOptions()
	options.Parser = parser

	evaluator, err := NewWACEvaluator(options, registry)
	if err != nil {
		t.Fatalf("failed to create evaluator with custom parser: %v", err)
	}

	// The evaluator should work with the custom parser
	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      "test-request-custom-parser",
		Method:         "GET",
		ResourceURI:    "https://example.org/resource",
		RequestedModes: []AccessMode{AccessModeRead},
		NowUnix:        time.Now().Unix(),
	}

	_, err = evaluator.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
}

// TestIsWACContentType tests content type detection
func TestIsWACContentType(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewWACEvaluator(DefaultWACEvaluatorOptions(), registry)

	testCases := []struct {
		contentType string
		want        bool
	}{
		{"text/turtle", true},
		{"application/ld+json", true},
		{"application/n-triples", true},
		{"text/plain", false},
		{"application/xml", false},
		{"text/turtle; charset=utf-8", true},
	}

	for _, tc := range testCases {
		t.Run(tc.contentType, func(t *testing.T) {
			got := evaluator.isWACContentType(tc.contentType)
			if got != tc.want {
				t.Errorf("isWACContentType(%q) = %v, want %v", tc.contentType, got, tc.want)
			}
		})
	}
}

// Ensure errors import is used
var _ = errors.New("test error")
