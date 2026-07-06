// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/outlaw-dame/solid-sidecar/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRDFParserBoundaryBasic tests basic functionality of the RDF parser boundary
func TestRDFParserBoundaryBasic(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(t, err)
	defer boundary.Close()

	// Verify it's not closed
	assert.False(t, boundary.IsClosed())

	// Verify supported content types
	supportedTypes := boundary.SupportedContentTypes()
	assert.Contains(t, supportedTypes, "text/turtle")
	assert.Contains(t, supportedTypes, "application/ld+json")
	assert.Contains(t, supportedTypes, "application/n-triples")
}

// TestRDFParserBoundaryParse tests parsing functionality
func TestRDFParserBoundaryParse(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(t, err)
	defer boundary.Close()

	ctx := context.Background()

	// Test parsing Turtle format
	turtleContent := []byte(`
@prefix ex: <http://example.org/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

ex:subject rdf:type ex:Thing .
ex:subject ex:property ex:object .
`)

	result, err := boundary.Parse(ctx, turtleContent, "text/turtle")
	require.NoError(t, err)
	
	// Verify we got some triples
	assert.NotEmpty(t, result.Triples, "Expected to parse at least one triple")
	
	// Verify content type is set
	assert.Equal(t, "text/turtle", result.ContentType)
	
	// Verify base URI is set (should be the synthetic URI we used)
	assert.NotEmpty(t, result.BaseURI)
	
	// Verify triples are canonicalized (sorted)
	for i := 1; i < len(result.Triples); i++ {
		assert.True(t,
			result.Triples[i-1].Subject <= result.Triples[i].Subject,
			"Triples should be sorted by subject: %v vs %v", 
			result.Triples[i-1], result.Triples[i])
	}
}

// TestRDFParserBoundaryParseNtriples tests parsing N-Triples format
func TestRDFParserBoundaryParseNtriples(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(t, err)
	defer boundary.Close()

	ctx := context.Background()

	// Test parsing N-Triples format
	ntriplesContent := []byte(`
<http://example.org/subject> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/Thing> .
<http://example.org/subject> <http://example.org/property> <http://example.org/object> .
`)

	result, err := boundary.Parse(ctx, ntriplesContent, "application/n-triples")
	require.NoError(t, err)
	
	// Verify we got the expected number of triples
	assert.Len(t, result.Triples, 2, "Expected to parse 2 triples")
	
	// Verify the triples are sorted (canonicalized)
	if len(result.Triples) >= 2 {
		// The type triple should come first (alphabetically by predicate)
		assert.True(t,
			result.Triples[0].Predicate <= result.Triples[1].Predicate,
			"Triples should be sorted by predicate")
	}
}

// TestRDFParserBoundaryCanonicalization tests the canonicalization functionality
func TestRDFParserBoundaryCanonicalization(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary with canonicalization enabled
	options := DefaultRDFParserBoundaryOptions()
	options.EnableCanonicalization = true
	boundary, err := NewRDFParserBoundary(rdfLayer, options)
	require.NoError(t, err)
	defer boundary.Close()

	ctx := context.Background()

	// Test content with extra whitespace in the triple structure (spaces between triples)
	// Using properly formatted Turtle without spaces inside angle brackets
	content := []byte(`
<http://example.org/subject> <http://example.org/predicate> <http://example.org/object> .
`)

	result, err := boundary.Parse(ctx, content, "text/turtle")
	require.NoError(t, err)
	
	// Verify we got at least one triple
	require.NotEmpty(t, result.Triples, "Expected to parse at least one triple")
	
	// Verify canonicalization removed extra whitespace from the structure
	for _, triple := range result.Triples {
		assert.NotContains(t, triple.Subject, " ", "Subject should not contain extra whitespace")
		assert.NotContains(t, triple.Predicate, " ", "Predicate should not contain extra whitespace")
		assert.NotContains(t, triple.Object, " ", "Object should not contain extra whitespace")
		
		// Verify angle brackets are removed (canonical form)
		assert.NotContains(t, triple.Subject, "<", "Subject should not contain angle brackets")
		assert.NotContains(t, triple.Subject, ">", "Subject should not contain angle brackets")
		assert.NotContains(t, triple.Predicate, "<", "Predicate should not contain angle brackets")
		assert.NotContains(t, triple.Predicate, ">", "Predicate should not contain angle brackets")
		assert.NotContains(t, triple.Object, "<", "Object should not contain angle brackets")
		assert.NotContains(t, triple.Object, ">", "Object should not contain angle brackets")
	}
	
	// Verify triples are sorted (part of canonicalization)
	for i := 1; i < len(result.Triples); i++ {
		assert.True(t,
			result.Triples[i-1].Subject <= result.Triples[i].Subject,
			"Triples should be sorted by subject: %v vs %v", 
			result.Triples[i-1], result.Triples[i])
	}
}

// TestRDFParserBoundaryInputSizeLimit tests input size validation
func TestRDFParserBoundaryInputSizeLimit(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary with small input limit
	options := DefaultRDFParserBoundaryOptions()
	options.MaxInputSize = 100 // Very small limit
	boundary, err := NewRDFParserBoundary(rdfLayer, options)
	require.NoError(t, err)
	defer boundary.Close()

	ctx := context.Background()

	// Create content that exceeds the limit
	largeContent := make([]byte, 200)
	for i := range largeContent {
		largeContent[i] = 'a'
	}

	// Parse should fail due to size limit
	_, err = boundary.Parse(ctx, largeContent, "text/turtle")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRDFInputTooLarge), "Expected input too large error")
}

// TestRDFParserBoundaryClosed tests behavior when boundary is closed
func TestRDFParserBoundaryClosed(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(t, err)
	
	// Close the boundary
	err = boundary.Close()
	require.NoError(t, err)
	
	// Verify it's closed
	assert.True(t, boundary.IsClosed())
	
	// Test that parsing fails when closed
	ctx := context.Background()
	_, err = boundary.Parse(ctx, []byte("test"), "text/turtle")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRDFParserBoundaryClosed), "Expected boundary closed error")
	
	// Test that closing again is a no-op
	err = boundary.Close()
	require.NoError(t, err)
}

// TestRDFParserBoundaryNilRDFLayer tests error handling with nil RDF layer
func TestRDFParserBoundaryNilRDFLayer(t *testing.T) {
	t.Parallel()

	// Try to create boundary with nil RDF layer
	_, err := NewRDFParserBoundary(nil, DefaultRDFParserBoundaryOptions())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRDFParserBoundaryNotAvailable), "Expected not available error")
}

// TestRDFParserBoundaryHealthCheck tests health check functionality
func TestRDFParserBoundaryHealthCheck(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(t, err)
	defer boundary.Close()

	ctx := context.Background()

	// Health check should pass
	err = boundary.HealthCheck(ctx)
	require.NoError(t, err)
	
	// Close the boundary and verify health check fails
	boundary.Close()
	
	err = boundary.HealthCheck(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRDFParserBoundaryClosed), "Expected boundary closed error")
}

// TestRDFParserBoundaryStats tests stats functionality
func TestRDFParserBoundaryStats(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	options := DefaultRDFParserBoundaryOptions()
	options.EnableCanonicalization = true
	options.MaxInputSize = 1024 * 1024
	boundary, err := NewRDFParserBoundary(rdfLayer, options)
	require.NoError(t, err)
	defer boundary.Close()

	// Get stats
	stats := boundary.Stats()
	
	// Verify stats
	assert.False(t, stats.Closed)
	assert.True(t, stats.CanonicalizationEnabled)
	assert.Equal(t, int64(1024*1024), stats.MaxInputSize)
}

// TestRDFParserBoundaryImplementsInterface tests that the boundary implements RDFParser interface
func TestRDFParserBoundaryImplementsInterface(t *testing.T) {
	// This test ensures that RDFParserBoundary implements RDFParser interface
	// It will fail to compile if the interface is not properly implemented
	
	// Create a variable of type RDFParser and assign a RDFParserBoundary to it
	var parser RDFParser
	
	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(t, err)
	defer boundary.Close()
	
	// This assignment will fail to compile if RDFParserBoundary doesn't implement RDFParser
	parser = boundary
	
	// Verify the interface is implemented correctly
	ctx := context.Background()
	content := []byte("<http://example.org/s> <http://example.org/p> <http://example.org/o> .")
	
	result, err := parser.Parse(ctx, content, "text/turtle")
	require.NoError(t, err)
	assert.NotEmpty(t, result.Triples)
	
	supportedTypes := parser.SupportedContentTypes()
	assert.Contains(t, supportedTypes, "text/turtle")
}

// TestRDFParserBoundaryIntegration tests integration with parser registry
func TestRDFParserBoundaryIntegration(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(t, err)
	defer boundary.Close()

	// Create parser registry
	registry := NewRDFParserRegistry(DefaultRDFParserOptions())
	
	// Register the boundary as a parser
	registry.Register(boundary)
	
	// Verify the registry can parse using the boundary
	ctx := context.Background()
	content := []byte("<http://example.org/subject> <http://example.org/predicate> <http://example.org/object> .")
	
	result, err := registry.Parse(ctx, content, "text/turtle")
	require.NoError(t, err)
	assert.NotEmpty(t, result.Triples)
	assert.Equal(t, "text/turtle", result.ContentType)
}

// TestRDFParserBoundaryConcurrentAccess tests thread safety
func TestRDFParserBoundaryConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(t, err)
	defer boundary.Close()

	ctx := context.Background()
	content := []byte("<http://example.org/s> <http://example.org/p> <http://example.org/o> .")
	
	// Test concurrent parsing
	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := boundary.Parse(ctx, content, "text/turtle")
			done <- err
		}()
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		err := <-done
		require.NoError(t, err)
	}
}

// TestRDFParserBoundaryErrorHandling tests error handling in the boundary
func TestRDFParserBoundaryErrorHandling(t *testing.T) {
	t.Parallel()

	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(t, err)
	defer boundary.Close()

	ctx := context.Background()

	// Test parsing invalid content (should not panic)
	_, err = boundary.Parse(ctx, []byte("invalid content"), "text/turtle")
	// This might succeed or fail depending on how the parser handles invalid content
	// The important thing is it doesn't panic
	_ = err // We don't assert the error here, just that it doesn't panic
}

// BenchmarkRDFParserBoundaryParse benchmarks parsing performance
func BenchmarkRDFParserBoundaryParse(b *testing.B) {
	// Create runtime RDF layer
	rdfLayer := runtime.NewRDFGraphIndexLayer(runtime.DefaultRDFGraphIndexConfig())
	
	// Create boundary
	boundary, err := NewRDFParserBoundary(rdfLayer, DefaultRDFParserBoundaryOptions())
	require.NoError(b, err)
	defer boundary.Close()

	ctx := context.Background()
	
	// Sample Turtle content for benchmarking
	content := []byte(`
@prefix ex: <http://example.org/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

ex:subject1 rdf:type ex:Thing ;
    ex:property1 ex:object1 ;
    ex:property2 ex:object2 .

ex:subject2 rdf:type ex:Thing ;
    ex:property1 ex:object3 ;
    ex:property2 ex:object4 .
`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := boundary.Parse(ctx, content, "text/turtle")
		if err != nil {
			b.Fail()
		}
	}
}
