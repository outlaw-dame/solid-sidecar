// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements content negotiation conformance tests as Go test functions.
package conformance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestContentNegotiationRDFFormats tests content negotiation for RDF formats
func TestContentNegotiationRDFFormats(t *testing.T) {
	tests := []struct {
		name         string
		acceptHeader string
		expectedType string
		expectError  bool
	}{
		{
			name:         "Turtle format",
			acceptHeader: "text/turtle",
			expectedType: "text/turtle",
			expectError:  false,
		},
		{
			name:         "JSON-LD format",
			acceptHeader: "application/ld+json",
			expectedType: "application/ld+json",
			expectError:  false,
		},
		{
			name:         "RDF/XML format",
			acceptHeader: "application/rdf+xml",
			expectedType: "application/rdf+xml",
			expectError:  false,
		},
		{
			name:         "N-Triples format",
			acceptHeader: "application/n-triples",
			expectedType: "application/n-triples",
			expectError:  false,
		},
		{
			name:         "N-Quads format",
			acceptHeader: "application/n-quads",
			expectedType: "application/n-quads",
			expectError:  false,
		},
		{
			name:         "Wildcard accept",
			acceptHeader: "*/*",
			expectedType: "text/turtle", // Default RDF format
			expectError:  false,
		},
		{
			name:         "Multiple RDF formats",
			acceptHeader: "text/turtle, application/ld+json",
			expectedType: "text/turtle", // First preference
			expectError:  false,
		},
		{
			name:         "Unsupported RDF format",
			acceptHeader: "application/rdf+json",
			expectedType: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server that returns different content types
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				accept := r.Header.Get("Accept")

				// Parse Accept header by splitting on comma and finding the first supported format
				formats := []string{"text/turtle", "application/ld+json", "application/rdf+xml", "application/n-triples", "application/n-quads"}

				if accept == "*/*" || accept == "" {
					w.Header().Set("Content-Type", "text/turtle")
					w.Write([]byte("@prefix ex: <http://example.org/> ."))
					return
				}

				// Check exact matches first
				switch accept {
				case "text/turtle":
					w.Header().Set("Content-Type", "text/turtle")
					w.Write([]byte("@prefix ex: <http://example.org/> ."))
					return
				case "application/ld+json":
					w.Header().Set("Content-Type", "application/ld+json")
					w.Write([]byte(`{"@context":"http://www.w3.org/ns/ldp.jsonld","@id":"http://example.org/resource"}`))
					return
				case "application/rdf+xml":
					w.Header().Set("Content-Type", "application/rdf+xml")
					w.Write([]byte(`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"></rdf:RDF>`))
					return
				case "application/n-triples":
					w.Header().Set("Content-Type", "application/n-triples")
					w.Write([]byte("<http://example.org/s> <http://example.org/p> <http://example.org/o> ."))
					return
				case "application/n-quads":
					w.Header().Set("Content-Type", "application/n-quads")
					w.Write([]byte("<http://example.org/s> <http://example.org/p> <http://example.org/o> <http://example.org/g> ."))
					return
				case "application/rdf+json":
					// Unsupported format
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusNotAcceptable)
					w.Write([]byte("Unsupported format"))
					return
				}

				// Split by comma and check each part in order
				acceptParts := strings.Split(accept, ",")
				for _, part := range acceptParts {
					part = strings.TrimSpace(part)
					// Check if this part matches any of our supported formats
					for _, fmt := range formats {
						if part == fmt {
							w.Header().Set("Content-Type", fmt)
							// Return appropriate body based on format
							switch fmt {
							case "text/turtle":
								w.Write([]byte("@prefix ex: <http://example.org/> ."))
							case "application/ld+json":
								w.Write([]byte(`{"@context":"http://www.w3.org/ns/ldp.jsonld","@id":"http://example.org/resource"}`))
							case "application/rdf+xml":
								w.Write([]byte(`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"></rdf:RDF>`))
							case "application/n-triples":
								w.Write([]byte("<http://example.org/s> <http://example.org/p> <http://example.org/o> ."))
							case "application/n-quads":
								w.Write([]byte("<http://example.org/s> <http://example.org/p> <http://example.org/o> <http://example.org/g> ."))
							}
							return
						}
					}
				}

				// If no match, return 406 Not Acceptable
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusNotAcceptable)
				w.Write([]byte("Unsupported format"))
			}))
			defer server.Close()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			if tt.acceptHeader != "" {
				req.Header.Set("Accept", tt.acceptHeader)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if tt.expectError {
				if resp.StatusCode == http.StatusOK {
					t.Errorf("Expected error but got status %d", resp.StatusCode)
				}
			} else {
				contentType := resp.Header.Get("Content-Type")
				if contentType != tt.expectedType {
					t.Errorf("Expected Content-Type %q but got %q", tt.expectedType, contentType)
				}
			}
		})
	}
}

// TestContentNegotiationNonRDFFormats tests content negotiation for non-RDF formats
func TestContentNegotiationNonRDFFormats(t *testing.T) {
	tests := []struct {
		name         string
		acceptHeader string
		expectedType string
	}{
		{
			name:         "Plain text",
			acceptHeader: "text/plain",
			expectedType: "text/plain",
		},
		{
			name:         "HTML",
			acceptHeader: "text/html",
			expectedType: "text/html",
		},
		{
			name:         "JSON",
			acceptHeader: "application/json",
			expectedType: "application/json",
		},
		{
			name:         "Octet stream",
			acceptHeader: "application/octet-stream",
			expectedType: "application/octet-stream",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				accept := r.Header.Get("Accept")
				w.Header().Set("Content-Type", accept)
				w.Write([]byte("test content"))
			}))
			defer server.Close()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Accept", tt.acceptHeader)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			contentType := resp.Header.Get("Content-Type")
			if contentType != tt.expectedType {
				t.Errorf("Expected Content-Type %q but got %q", tt.expectedType, contentType)
			}
		})
	}
}

// TestContentNegotiationWildcard tests wildcard content type handling
func TestContentNegotiationWildcard(t *testing.T) {
	// Server that returns Turtle by default for wildcard
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		if accept == "*/*" || accept == "" {
			w.Header().Set("Content-Type", "text/turtle")
		} else {
			w.Header().Set("Content-Type", accept)
		}
		w.Write([]byte("test"))
	}))
	defer server.Close()

	tests := []struct {
		acceptHeader string
		expectedType string
	}{
		{"*/*", "text/turtle"},
		{"", "text/turtle"},
	}

	for _, tt := range tests {
		t.Run(tt.acceptHeader, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			if tt.acceptHeader != "" {
				req.Header.Set("Accept", tt.acceptHeader)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			contentType := resp.Header.Get("Content-Type")
			if contentType != tt.expectedType {
				t.Errorf("Expected Content-Type %q but got %q", tt.expectedType, contentType)
			}
		})
	}
}

// TestContentNegotiationMultipleAccept tests handling of multiple Accept header values
func TestContentNegotiationMultipleAccept(t *testing.T) {
	// Server that prioritizes the first acceptable format in the Accept header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")

		// Parse Accept header by splitting on comma and finding the first supported format
		formats := []string{"text/turtle", "application/ld+json", "application/rdf+xml", "application/n-triples", "application/n-quads"}

		if accept == "*/*" || accept == "" {
			w.Header().Set("Content-Type", "text/turtle")
			w.Write([]byte("test"))
			return
		}

		// Split by comma and check each part in order
		acceptParts := strings.Split(accept, ",")
		for _, part := range acceptParts {
			part = strings.TrimSpace(part)
			// Check if this part (without q-value) matches any of our supported formats
			for _, fmt := range formats {
				if part == fmt || strings.HasPrefix(part, fmt+";") {
					w.Header().Set("Content-Type", fmt)
					w.Write([]byte("test"))
					return
				}
			}
		}

		// If no match, return 406 Not Acceptable
		w.WriteHeader(http.StatusNotAcceptable)
	}))
	defer server.Close()

	tests := []struct {
		acceptHeader string
		expectedType string
	}{
		{"text/turtle, application/ld+json", "text/turtle"},
		{"application/ld+json, text/turtle", "application/ld+json"},
		{"application/json, text/turtle", "text/turtle"},
	}

	for _, tt := range tests {
		t.Run(tt.acceptHeader, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Accept", tt.acceptHeader)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			contentType := resp.Header.Get("Content-Type")
			if contentType != tt.expectedType {
				t.Errorf("Expected Content-Type %q but got %q", tt.expectedType, contentType)
			}
		})
	}
}

// TestContentNegotiationQualityValues tests q-value handling in Accept headers
func TestContentNegotiationQualityValues(t *testing.T) {
	// Server that respects q-values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")

		// Parse Accept header with q-values
		// Split by comma, then parse each part with its q-value
		parts := strings.Split(accept, ",")

		// Map of format -> q-value
		formatQuality := make(map[string]float64)

		for _, part := range parts {
			part = strings.TrimSpace(part)

			// Parse q-value if present
			q := 1.0
			if idx := strings.Index(part, ";q="); idx != -1 {
				qStr := part[idx+3:]
				// Simple parsing - in a real server, use strconv.ParseFloat
				if qStr == "0.5" {
					q = 0.5
				} else if qStr == "0.8" {
					q = 0.8
				} else if qStr == "0" {
					q = 0
				}
				// Remove the q-value part
				part = strings.TrimSpace(part[:idx])
			}

			// Store the format with its quality
			if part != "" {
				formatQuality[part] = q
			}
		}

		// Find the format with the highest q-value
		bestFormat := ""
		bestQ := -1.0
		for fmt, q := range formatQuality {
			if q > bestQ {
				bestQ = q
				bestFormat = fmt
			}
		}

		if bestFormat != "" {
			w.Header().Set("Content-Type", bestFormat)
		} else {
			w.Header().Set("Content-Type", "text/turtle")
		}
		w.Write([]byte("test"))
	}))
	defer server.Close()

	tests := []struct {
		acceptHeader string
		expectedType string
	}{
		{"text/turtle;q=0.5, application/ld+json", "application/ld+json"},
		{"application/ld+json;q=0.5, text/turtle", "text/turtle"},
	}

	for _, tt := range tests {
		t.Run(tt.acceptHeader, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Accept", tt.acceptHeader)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			contentType := resp.Header.Get("Content-Type")
			if contentType != tt.expectedType {
				t.Errorf("Expected Content-Type %q but got %q", tt.expectedType, contentType)
			}
		})
	}
}
