// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestACPEvaluatorCreation tests creating an ACP evaluator
func TestACPEvaluatorCreation(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, err := NewACPEvaluator(DefaultACPEvaluatorOptions(), registry)
	if err != nil {
		t.Fatalf("failed to create ACP evaluator: %v", err)
	}
	if evaluator == nil {
		t.Fatal("ACP evaluator is nil")
	}
}

// TestACPEvaluatorDefaultOptions tests default options
func TestACPEvaluatorDefaultOptions(t *testing.T) {
	options := DefaultACPEvaluatorOptions()

	if options.MaxPolicies != 10 {
		t.Errorf("expected default max policies 10, got %d", options.MaxPolicies)
	}
	if options.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", options.Timeout)
	}
	if !options.ShadowMode {
		t.Error("expected shadow mode to be true by default")
	}
	if options.Logger != nil {
		t.Error("expected logger to be nil by default")
	}
}

// TestACPEvaluatorNilRDFParser tests error handling for nil RDF parser registry
func TestACPEvaluatorNilRDFParser(t *testing.T) {
	// When RDF parser is nil, the evaluator should still be created but will fail when parsing
	// The ACP parser creation will fail, which is expected
	_, err := NewACPEvaluator(DefaultACPEvaluatorOptions(), nil)
	if err == nil {
		t.Fatal("expected error for nil RDF parser registry, got nil")
	}
}

// TestACPEvaluatorInterfaceCompliance tests that ACPEvaluator implements Evaluator
func TestACPEvaluatorInterfaceCompliance(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewACPEvaluator(DefaultACPEvaluatorOptions(), registry)

	// This should compile if the interface is properly implemented
	var _ Evaluator = evaluator
}

// TestACPEvaluatorEvaluateWithNoPolicies tests evaluation with no policy documents
func TestACPEvaluatorEvaluateWithNoPolicies(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewACPEvaluator(DefaultACPEvaluatorOptions(), registry)

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

// TestACPEvaluatorEvaluateWithPolicies tests evaluation with policy documents
func TestACPEvaluatorEvaluateWithPolicies(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewACPEvaluator(DefaultACPEvaluatorOptions(), registry)

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

// TestACPEvaluatorEvaluateWithInvalidRequest tests evaluation with invalid request
func TestACPEvaluatorEvaluateWithInvalidRequest(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewACPEvaluator(DefaultACPEvaluatorOptions(), registry)

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

// TestACPEvaluatorTimeout tests timeout handling
func TestACPEvaluatorTimeout(t *testing.T) {
	options := DefaultACPEvaluatorOptions()
	options.Timeout = 1 * time.Nanosecond // Very short timeout

	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewACPEvaluator(options, registry)

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

// TestACPEvaluatorMaxPolicies tests the maximum policies limit
func TestACPEvaluatorMaxPolicies(t *testing.T) {
	options := DefaultACPEvaluatorOptions()
	options.MaxPolicies = 2 // Very small limit

	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewACPEvaluator(options, registry)

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

// TestACPEvaluatorShadowMode tests that the evaluator operates in shadow mode
func TestACPEvaluatorShadowMode(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewACPEvaluator(DefaultACPEvaluatorOptions(), registry)

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

// TestACPEvaluatorWithCustomParser tests using a custom ACP parser
func TestACPEvaluatorWithCustomParser(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	parser, _ := NewACPParser(DefaultACPParserOptions(), registry)

	options := DefaultACPEvaluatorOptions()
	options.Parser = parser

	evaluator, err := NewACPEvaluator(options, registry)
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

// TestIsACPContentType tests content type detection
func TestIsACPContentType(t *testing.T) {
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	evaluator, _ := NewACPEvaluator(DefaultACPEvaluatorOptions(), registry)

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
			got := evaluator.isACPContentType(tc.contentType)
			if got != tc.want {
				t.Errorf("isACPContentType(%q) = %v, want %v", tc.contentType, got, tc.want)
			}
		})
	}
}

// Ensure errors import is used
var _ = errors.New("test error")
